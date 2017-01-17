//
//  main.swift
//  coconut
//
//  Created by leaves chen on 2017/1/17.
//
//

import Dispatch
#if os(Linux) // for sockaddr_in
    import Glibc
let sysSleep = Glibc.sleep
#else
    import Darwin
let sysSleep = Darwin.sleep
#endif

let port = 7777

let echod = Socks5Server(port: port)
echod.start()

print("Connect in e.g. Terminal via 'telnet 127.0.0.1 \(port)'")

dispatchMain()
// dispatch_main never returns. print("Stopping.")
