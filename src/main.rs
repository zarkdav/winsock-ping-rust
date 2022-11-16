/*
 Rust port of ping.exe from Network Programming for Microsoft Windows, Second Edition by
Anthony Jones and James Ohlund.
*/

use std::{
    alloc::{alloc, Layout},
    collections::VecDeque,
    ffi::c_void,
    io::{Error, ErrorKind},
    os::raw::{c_uchar, c_ulong, c_ushort},
};
use widestring::WideCString;
use windows_sys::Win32::{
    Foundation::{HANDLE, NO_ERROR, WAIT_FAILED, WAIT_TIMEOUT},
    Networking::WinSock::{
        bind, getnameinfo, sendto, setsockopt, socket, GetAddrInfoW, WSACreateEvent,
        WSAGetLastError, WSAGetOverlappedResult, WSAIoctl, WSARecvFrom, WSAResetEvent, WSAStartup,
        ADDRESS_FAMILY, ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC, AI_PASSIVE, INVALID_SOCKET,
        IPPROTO, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_ND,
        IPV6_UNICAST_HOPS, IP_OPTIONS, IP_TTL, NI_MAXHOST, NI_MAXSERV, NI_NUMERICHOST,
        NI_NUMERICSERV, SIO_ROUTING_INTERFACE_QUERY, SOCKADDR, SOCKADDR_STORAGE, SOCKET,
        SOCKET_ERROR, SOCK_RAW, WSABUF, WSADATA, WSA_IO_PENDING,
    },
    System::{
        SystemInformation::GetTickCount,
        Threading::{Sleep, WaitForSingleObject},
        IO::OVERLAPPED,
    },
};

struct Config {
    address_family: ADDRESS_FAMILY,
    ttl: u8,
    data_size: u32,
    record_route: bool,
    destination: String,
    protocol: IPPROTO,
}

#[repr(C)]
struct IcmpHdr {
    icmp_type: c_uchar,
    icmp_code: c_uchar,
    icmp_checksum: c_ushort,
    icmp_id: c_ushort,
    icmp_sequence: c_ushort,
}

#[repr(C)]
struct IcmpV6Hdr {
    icmp6_type: c_uchar,
    icmp6_code: c_uchar,
    icmp6_checksum: c_ushort,
}

#[repr(C)]
struct IcmpV6EchoRequest {
    icmp6_echo_id: c_ushort,
    icmp6_echo_sequence: c_ushort,
}

// we actually write to the fields through a Box::new
#[allow(dead_code)]
#[repr(C)]
struct IpV4OptionHdr {
    opt_code: c_uchar,
    opt_len: c_uchar,
    opt_ptr: c_uchar,
    opt_addr: [c_ulong; 9],
}

fn checksum(buf: *const u16, packetlen: usize) -> u16 {
    let mut cksum: u32 = 0;
    let mut buf = buf as *mut u16;
    let mut size = packetlen;

    while size > 1 {
        cksum += unsafe { *buf } as u32;
        buf = unsafe { buf.add(1) };
        size -= 2;
    }
    if size != 0 {
        let buf = buf as *const u8;
        cksum += unsafe { *buf } as u32;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += cksum >> 16;

    !cksum as u16
}

/* fn compute_icmp6_pseudoheader_checksum(
    s: &SOCKET,
    buf: *mut u16,
    packetlen: usize,
    dest: *const ADDRINFOW,
) {
} */

fn compute_icmp_checksum(
    s: &SOCKET,
    buf: *mut u8,
    packetlen: usize,
    dest: *const ADDRINFOW,
    config: &Config,
) {
    if config.address_family == AF_INET {
        let icmp_hdr = buf as *mut IcmpHdr;
        unsafe {
            (*icmp_hdr).icmp_checksum = 0;
            (*icmp_hdr).icmp_checksum = checksum(buf as *const u16, packetlen);
        }
    } /* else if config.address_family == AF_INET6 {
          let icmp6_hdr = buf as *mut IcmpV6Hdr;
          unsafe {
              (*icmp6_hdr).icmp6_checksum = 0;
              (*icmp6_hdr).icmp6_checksum =
                  compute_icmp6_pseudoheader_checksum(s, buf, packetlen, dest);
          }
      } */
}

fn set_icmp_sequence(buf: *mut u8, config: &Config) {
    let sequence = unsafe { GetTickCount() };

    if config.address_family == AF_INET {
        let icmp_hdr = buf as *mut IcmpHdr;
        unsafe {
            (*icmp_hdr).icmp_sequence = sequence as u16;
        }
    } else if config.address_family == AF_INET6 {
        unsafe {
            let icmp6_req = buf.add(std::mem::size_of::<IcmpV6Hdr>()) as *mut IcmpV6EchoRequest;
            (*icmp6_req).icmp6_echo_sequence = sequence as u16;
        }
    }
}

fn print_address(sa: *const SOCKADDR, len: usize) -> i32 {
    let pnodebuffer = [0u16; NI_MAXHOST as usize].as_mut_ptr();
    let nodebuffersize = NI_MAXHOST;
    let pservicebuffer = [0u16; NI_MAXSERV as usize].as_mut_ptr();
    let servicebuffersize = NI_MAXSERV;

    let rc = unsafe {
        GetNameInfoW(
            sa,
            len as i32,
            pnodebuffer,
            nodebuffersize,
            pservicebuffer,
            servicebuffersize,
            (NI_NUMERICHOST | NI_NUMERICSERV) as i32,
        )
    };

    if rc != 0 {
        eprintln!("GetNameInfoW failed: {}", Error::last_os_error());
        return rc;
    }

    let host = unsafe { WideCString::from_ptr_str(pnodebuffer).to_string().unwrap() };
    let serv = unsafe {
        WideCString::from_ptr_str(pservicebuffer)
            .to_string()
            .unwrap()
    };

    if serv != "0" {
        if (unsafe { (*sa).sa_family } == AF_INET as u16) {
            print!("[{}]:{}", host, serv);
        } else {
            print!("{}:{}", host, serv);
        }
    } else {
        print!("{}", host);
    }

    NO_ERROR as i32
}

fn post_recvfrom(
    s: SOCKET,
    buf: *mut u8,
    buflen: usize,
    from: *mut SOCKADDR,
    fromlen: &mut i32,
    ol: &mut OVERLAPPED,
) -> i32 {
    let mut bytes: u32 = 0;
    let mut flags: u32 = 0;
    let wbuf = Box::into_raw(Box::new(WSABUF {
        buf,
        len: buflen as u32,
    }));

    let rc = unsafe { WSARecvFrom(s, wbuf, 1, &mut bytes, &mut flags, from, fromlen, ol, None) };

    if rc == SOCKET_ERROR && unsafe { WSAGetLastError() } != WSA_IO_PENDING {
        eprintln!("WSARecvFrom failed: {}", Error::last_os_error());
    }

    rc
}

fn init_icmp_header(buf: *mut u8, len: usize) {
    let icmp_hdr = buf as *mut IcmpHdr;

    unsafe {
        (*icmp_hdr).icmp_type = 8; // Echo Request
        (*icmp_hdr).icmp_code = 0;
        (*icmp_hdr).icmp_id = std::process::id() as u16;
        (*icmp_hdr).icmp_checksum = 0;
        (*icmp_hdr).icmp_sequence = 0;

        let datapart = buf.add(std::mem::size_of::<IcmpHdr>());
        datapart.write_bytes(b'E', len);
    }
}

fn init_icmp6_header(buf: *mut u8, len: usize) {
    let icmp6_hdr = buf as *mut IcmpV6Hdr;

    unsafe {
        (*icmp6_hdr).icmp6_type = 128; // Echo Request
        (*icmp6_hdr).icmp6_code = 0;
        (*icmp6_hdr).icmp6_checksum = 0;

        let icmp6_req = buf.add(std::mem::size_of::<IcmpV6Hdr>()) as *mut IcmpV6EchoRequest;
        (*icmp6_req).icmp6_echo_id = std::process::id() as u16;
        (*icmp6_req).icmp6_echo_sequence = 0;

        let datapart = icmp6_req.add(1) as *mut u8;
        datapart.write_bytes(b'#', len);
    }
}

fn set_ttl(s: &SOCKET, config: &Config) -> Result<(), Error> {
    let (level, optname) = match config.address_family {
        AF_INET => (IPPROTO_IP as i32, IP_TTL),
        AF_INET6 => (IPPROTO_IPV6, IPV6_UNICAST_HOPS),
        _ => return Err(Error::from(ErrorKind::InvalidInput)),
    };

    let ttlp = &config.ttl as *const u8;

    let rc = unsafe { setsockopt(*s, level as i32, optname as i32, ttlp, 1i32) };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn resolve_address(
    addr: Option<&String>,
    port: String,
    af: ADDRESS_FAMILY,
    socktype: i32,
    proto: IPPROTO,
) -> Result<*mut *mut ADDRINFOW, std::io::Error> {
    let mut service_name: Vec<u16> = port.encode_utf16().collect();
    service_name.push(0);

    let mut node_name: Vec<u16> = match addr {
        Some(addr) => addr.encode_utf16().collect(),
        None => Vec::new(),
    };
    node_name.push(0);

    let hints = Box::new(ADDRINFOW {
        ai_flags: match addr {
            Some(_) => 0,
            None => AI_PASSIVE as i32,
        },
        ai_family: af as i32,
        ai_socktype: socktype,
        ai_protocol: proto,
        ai_addr: std::ptr::null_mut() as *mut _,
        ai_canonname: std::ptr::null_mut() as *mut _,
        ai_next: std::ptr::null_mut() as *mut _,
        ai_addrlen: 0,
    });

    let ai = Box::new(ADDRINFOW {
        ai_flags: 0,
        ai_family: af as i32,
        ai_socktype: socktype,
        ai_protocol: proto,
        ai_addr: std::ptr::null_mut() as *mut _,
        ai_canonname: std::ptr::null_mut() as *mut _,
        ai_next: std::ptr::null_mut() as *mut _,
        ai_addrlen: 0,
    });
    let pai = Box::into_raw(ai) as *mut ADDRINFOW;
    let res = pai as *mut *mut ADDRINFOW;

    unsafe {
        let rc = GetAddrInfoW(
            node_name.as_ptr(),
            service_name.as_ptr(),
            Box::into_raw(hints),
            res,
        );
        if rc != 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(res.to_owned())
}

fn usage(progname: String) {
    eprintln!("usage: {progname} [options] <host>");
    eprintln!("        host        Remote machine to ping");
    eprintln!("        options:");
    eprintln!("            -a 4|6       Address family (default: AF_UNSPEC)");
    eprintln!("            -i ttl       Time to live (default: 128)");
    eprintln!("            -l bytes     Amount of data to send (default: 32)");
    eprintln!("            -r           Record route (IPv4 only)");
}

fn validate_args() -> Result<Config, std::io::Error> {
    let mut args: VecDeque<String> = std::env::args().collect();
    let mut config = Config {
        address_family: AF_UNSPEC,
        ttl: 128,
        data_size: 32,
        record_route: false,
        destination: String::from(""),
        protocol: IPPROTO_ND,
    };

    let progname = args.pop_front().unwrap();

    while let Some(arg) = args.pop_front() {
        if arg.starts_with(|c| c == '/' || c == '-') {
            match arg.chars().nth(1) {
                // address family
                Some('a') => match args.pop_front() {
                    Some(arg) => match &arg as &str {
                        "4" => config.address_family = AF_INET,
                        "6" => config.address_family = AF_INET6,
                        _ => return Err(Error::new(ErrorKind::InvalidInput, progname)),
                    },
                    None => return Err(Error::new(ErrorKind::InvalidInput, progname)),
                },
                Some('i') => match args.pop_front() {
                    Some(arg) => {
                        config.ttl = match arg.parse() {
                            Ok(i) => i,
                            Err(_) => return Err(Error::new(ErrorKind::InvalidInput, progname)),
                        }
                    }
                    None => return Err(Error::new(ErrorKind::InvalidInput, progname)),
                },
                Some('l') => match args.pop_front() {
                    Some(arg) => {
                        config.data_size = match arg.parse() {
                            Ok(i) => i,
                            Err(_) => return Err(Error::new(ErrorKind::InvalidInput, progname)),
                        }
                    }
                    None => return Err(Error::new(ErrorKind::InvalidInput, progname)),
                },
                Some('b') => config.record_route = true,
                _ => return Err(Error::new(ErrorKind::InvalidInput, progname)),
            }
        } else {
            config.destination = arg;
        }
    }

    if config.destination.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, progname));
    }
    Ok(config)
}

fn main() {
    // parse the command line
    let mut config = match validate_args() {
        Ok(config) => config,
        Err(e) => {
            usage(e.to_string());
            std::process::exit(-1);
        }
    };

    // load winsock
    const WINSOCK_VERSION: u16 = 0x202; // 2.2
    unsafe {
        let mut wsd: WSADATA = std::mem::zeroed();
        let rc = WSAStartup(WINSOCK_VERSION, &mut wsd as *mut WSADATA);
        if rc != 0 {
            eprintln!("WSAStartup failed: {rc}");
            std::process::exit(-1);
        }
    }

    // resolve the destination address
    let dest = match resolve_address(
        Some(&config.destination),
        String::from("0"),
        config.address_family,
        0,
        0,
    ) {
        Err(e) => {
            eprintln!("bad name {}: error {}", config.destination, e);
            std::process::exit(-1);
        }
        Ok(dest) => dest,
    };

    config.address_family = unsafe { (*(*dest)).ai_family as u32 };

    config.protocol = match config.address_family {
        AF_INET => IPPROTO_ICMP,
        AF_INET6 => IPPROTO_ICMPV6,
        _ => {
            eprintln!("unsupported address family: {}", config.address_family);
            std::process::exit(-1);
        }
    };

    // get the bind address
    /* This was in the original code and generates the wrong result (first IP address of whichever interface comes first)
        let local = match resolve_address(None, String::from("0"), config.address_family, 0, 0) {
            Err(e) => {
                eprintln!("Unable to obtain the bind address: error {}", e);
                std::process::exit(-1);
            }
            Ok(dest) => dest,
        };
    */
    // create the raw socket
    let s = unsafe {
        socket(
            config.address_family as i32,
            SOCK_RAW as i32,
            config.protocol,
        )
    };
    if s == INVALID_SOCKET {
        eprintln!("socket failed: {}", Error::last_os_error());
        std::process::exit(-1);
    }

    if set_ttl(&s, &config).is_err() {
        eprintln!("could not set TTL");
        std::process::exit(-1);
    }

    // figure out the size of the ICMP header and payload
    let mut packetlen = match config.address_family {
        AF_INET => std::mem::size_of::<IcmpHdr>(),
        AF_INET6 => std::mem::size_of::<IcmpV6Hdr>() + std::mem::size_of::<IcmpV6EchoRequest>(),
        _ => {
            eprintln!("unsupported address family: {}", config.address_family);
            std::process::exit(-1);
        }
    };

    // add the data size
    packetlen += config.data_size as usize;

    // allocate the buffer that will contain the ICMP request
    let layout = match Layout::from_size_align(packetlen, 1usize) {
        Ok(layout) => layout,
        Err(_) => {
            eprintln!("could not compute layout for {} usize packetlen", packetlen);
            std::process::exit(-1);
        }
    };

    let icmpbuf = unsafe { alloc(layout) };
    if icmpbuf.is_null() {
        eprintln!(
            "could not allocate {} usize for packet buffer using layout {:?}",
            packetlen, layout
        )
    }

    // initialize the ICMP headers
    match config.address_family {
        AF_INET => {
            // verified, see <https://flylib.com/books/en/3.223.1.87/1/>
            if config.record_route {
                let ipopt = Box::new(IpV4OptionHdr {
                    opt_code: 0x7, // Record Route
                    opt_ptr: 4,
                    opt_len: 39,
                    opt_addr: [0; 9],
                });

                if (unsafe {
                    setsockopt(
                        s,
                        IPPROTO_IP as i32,
                        IP_OPTIONS as i32,
                        Box::into_raw(ipopt) as *const u8,
                        std::mem::size_of::<IpV4OptionHdr>() as i32,
                    )
                } != 0)
                {
                    eprintln!("setsockopt(IP_OPTIONS failed: {}", Error::last_os_error());
                    std::process::exit(-1);
                }
            }
            init_icmp_header(icmpbuf, config.data_size as usize);
        }
        AF_INET6 => {
            init_icmp6_header(icmpbuf, packetlen);
        }
        _ => {
            eprintln!("unsupported address family: {}", config.address_family);
            std::process::exit(-1);
        }
    };

    // obtain the address of the local interface to send to dest
    let mut src = vec![0u8; 1024].as_mut_ptr();
    let psrc: *mut c_void = &mut src as *mut _ as *mut c_void;
    let mut bytes: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            s,
            SIO_ROUTING_INTERFACE_QUERY,
            (*(*dest)).ai_addr as *const _,
            (*(*dest)).ai_addrlen as u32,
            psrc,
            1024,
            &mut bytes as *mut _,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        eprintln!("WSAIoctl failed: {}", Error::last_os_error());
    }

    // bind the socket
    // if unsafe { bind(s, (*(*local)).ai_addr, (*(*local)).ai_addrlen as i32) } != 0 {

    let plocal = psrc as *mut SOCKADDR;
    let local = unsafe { &mut *plocal };
    if unsafe { bind(s, local, bytes as i32) } != 0 {
        eprintln!("bind failed: {}", Error::last_os_error());
        std::process::exit(-1);
    }

    // setup the receive operation
    const WSA_INVALID_EVENT: HANDLE = 0;
    let mut recvol: OVERLAPPED;
    unsafe {
        recvol = std::mem::zeroed();
        recvol.hEvent = WSACreateEvent();
        if recvol.hEvent == WSA_INVALID_EVENT {
            eprint!("WSACreateEvent failed: {}", Error::last_os_error());
            std::process::exit(-1);
        }
    };

    // post the first overlapped receive
    const MAX_RECV_BUFLEN: usize = 0xffff; // large packet size! but that's what the original code used
    let recvbuf_len = MAX_RECV_BUFLEN;
    let recvbuf = vec![0u8; MAX_RECV_BUFLEN].as_mut_ptr();
    let from = Box::into_raw(Box::new(SOCKADDR {
        sa_family: 0,
        sa_data: [0; 14],
    }));
    let mut fromlen = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;

    post_recvfrom(s, recvbuf, recvbuf_len, from, &mut fromlen, &mut recvol);

    print!("\nPinging ");
    unsafe { print_address((*(*dest)).ai_addr, (*(*dest)).ai_addrlen) };
    println!(" with {} bytes of data\n", config.data_size);

    // start sending ICMP requests
    for i in 0..4 {
        // set the sequence number and compute the checksum
        set_icmp_sequence(icmpbuf, &config);
        compute_icmp_checksum(&s, icmpbuf, packetlen, dest as *const _, &config);

        let mut time = unsafe { GetTickCount() };

        let mut rc = unsafe {
            sendto(
                s,
                icmpbuf,
                packetlen as i32,
                0,
                (*(*dest)).ai_addr,
                (*(*dest)).ai_addrlen as i32,
            ) as u32
        };
        if rc == SOCKET_ERROR as u32 {
            eprintln!("sendto failed: {}", Error::last_os_error());
            std::process::exit(-1);
        }

        // wait for response
        let mut bytes = 0;
        let mut flags = 0;
        rc = unsafe { WaitForSingleObject(recvol.hEvent, 6000) }; // default timeout of 6s
        if rc == WAIT_FAILED {
            eprintln!("WaitForSingleObject failed: {}", Error::last_os_error());
            std::process::exit(-1);
        } else if rc == WAIT_TIMEOUT {
            println!("Request timed out.");
        } else {
            rc = unsafe {
                WSAGetOverlappedResult(s, &recvol, &mut bytes, 0 /* FALSE */, &mut flags) as u32
            };
            if rc == 0
            /* FALSE */
            {
                eprintln!("WSAGetOverlappedResult failed: {}", Error::last_os_error());
            }
            time = unsafe { GetTickCount() } - time;

            unsafe { WSAResetEvent(recvol.hEvent) };

            print!("Reply from ");
            print_address(from, fromlen as usize);
            if time == 0 {
                println!(": bytes={} time<1ms TTL={}", config.data_size, config.ttl);
            } else {
                println!(
                    ": bytes={} time={}ms TTL={}",
                    config.data_size, time, config.ttl
                );
            }

            if i < 3 {
                post_recvfrom(s, recvbuf, recvbuf_len, from, &mut fromlen, &mut recvol);
            }
        }
        unsafe { Sleep(1000) };
    }
    // cleanup
}

/*

#[cfg(test)]
mod tests {
    use super::*;


}

 */
