extern crate libc;

use libc::{
    c_char, c_int, c_short, c_uint, c_ulong, c_void, getsockopt, if_nametoindex, ioctl, setsockopt,
    socket, socklen_t, ETH_P_ALL, IF_NAMESIZE, SOCK_RAW, SOL_PACKET,
};
pub use libc::{AF_PACKET, IFF_PROMISC, PF_PACKET};

use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

const IFREQUNIONSIZE: usize = 24;

const SIOCGIFFLAGS: c_ulong = 35091; //0x00008913;
const SIOCSIFFLAGS: c_ulong = 35092; //0x00008914;

pub const PACKET_FANOUT: c_int = 18;

#[repr(C)]
struct IfReq {
    //TODO: these are actually both unions, implement them as such now that Rust supports it
    ifr_name: [c_char; IF_NAMESIZE],
    data: [u8; IFREQUNIONSIZE],
}

impl IfReq {
    fn as_short(&self) -> c_short {
        c_short::from_be((self.data[0] as c_short) << 8 | (self.data[1] as c_short))
    }

    fn from_short(i: c_short) -> IfReq {
        let mut req = IfReq::default();
        //TODO: find a better way to do this
        let bytes: [u8; 2] = unsafe { mem::transmute(i) };
        req.data[0] = bytes[0];
        req.data[1] = bytes[1];
        req
    }

    fn with_if_name(if_name: &str) -> Result<IfReq> {
        let mut if_req = IfReq::default();

        if if_name.len() >= if_req.ifr_name.len() {
            return Err(Error::new(ErrorKind::Other, "Interface name too long"));
        }

        // basically a memcpy
        for (a, c) in if_req.ifr_name.iter_mut().zip(if_name.bytes()) {
            *a = c as i8;
        }

        Ok(if_req)
    }

    fn ifr_flags(&self) -> c_short {
        self.as_short()
    }
}

impl Default for IfReq {
    fn default() -> IfReq {
        IfReq {
            ifr_name: [0; IF_NAMESIZE],
            data: [0; IFREQUNIONSIZE],
        }
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct FilterProgram {
    len: u16,
    filter: *const Filter,
}

#[derive(Clone, Debug)]
pub struct Socket {
    ///File descriptor
    pub fd: c_int,
    ///Interface name
    pub if_name: String,
    pub if_index: c_uint,
    pub sock_type: c_int,
}

impl Socket {
    pub fn from_if_name(if_name: &str, socket_type: c_int) -> Result<Socket> {
        //this typecasting sucks :(
        let fd = unsafe { socket(socket_type, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        Ok(Socket {
            if_name: String::from(if_name),
            if_index: get_if_index(if_name)?,
            sock_type: socket_type,
            fd,
        })
    }

    fn ioctl(&self, ident: c_ulong, if_req: IfReq) -> Result<IfReq> {
        let mut req: Box<IfReq> = Box::new(if_req);
        match unsafe { ioctl(self.fd, ident, &mut *req) } {
            -1 => Err(Error::last_os_error()),
            _ => Ok(*req),
        }
    }

    fn get_flags(&self) -> Result<IfReq> {
        self.ioctl(SIOCGIFFLAGS, IfReq::with_if_name(&self.if_name)?)
    }

    pub fn set_flag(&mut self, flag: c_ulong) -> Result<()> {
        let flags = &self.get_flags()?.ifr_flags();
        let new_flags = flags | flag as c_short;
        let mut if_req = IfReq::with_if_name(&self.if_name)?;
        if_req.data = IfReq::from_short(new_flags).data;
        self.ioctl(SIOCSIFFLAGS, if_req)?;
        Ok(())
    }

    pub fn setsockopt<T>(&mut self, opt: c_int, opt_val: T) -> Result<()> {
        match unsafe {
            setsockopt(
                self.fd,
                SOL_PACKET,
                opt,
                &opt_val as *const _ as *const c_void,
                mem::size_of_val(&opt_val) as socklen_t,
            )
        } {
            0 => Ok(()),
            _ => Err(Error::last_os_error()),
        }
    }

    pub fn getsockopt(&mut self, opt: c_int, opt_val: &*mut c_void) -> Result<()> {
        get_sock_opt(self.fd, opt, opt_val)
    }

    pub fn set_non_blocking(&mut self) -> Result<()> {
        unsafe {
            let mut res = libc::fcntl(self.fd, libc::F_GETFL);
            if res != -1 {
                res = libc::fcntl(self.fd, libc::F_SETFL, res | libc::O_NONBLOCK);
            }
            if res == -1 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn set_bpf_filter(&self, program: FilterProgram) -> Result<()> {
        unsafe {
            let res = setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &program as *const _ as *const libc::c_void,
                std::mem::size_of::<FilterProgram>() as u32,
            );
            if res == -1 {
                return Err(Error::last_os_error());
            }
        }

        Ok(())
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

pub fn get_sock_opt(fd: i32, opt: c_int, opt_val: &*mut c_void) -> Result<()> {
    let mut optlen = mem::size_of_val(&opt_val) as socklen_t;
    match unsafe { getsockopt(fd, SOL_PACKET, opt, *opt_val, &mut optlen) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub fn get_if_index(name: &str) -> Result<c_uint> {
    let name = CString::new(name)?;
    let index = unsafe { if_nametoindex(name.as_ptr()) };
    Ok(index)
}
