//
//  Socks5Server.swift
//  coconut
//
//  Created by leaves chen on 2017/1/17.
//
//

import SwiftSockets
import Dispatch

#if os(Linux) // for sockaddr_in
    import Glibc
#else
    import Darwin
#endif

class Socks5Server {
    
    let port         : Int
    var listenSocket : PassiveSocketIPv4?
    let lockQueue    = DispatchQueue(label: "cn.leaves.coonut.socks5.socklock")
    var openSockets  =
        [FileDescriptor:ActiveSocket<sockaddr_in>](minimumCapacity: 8)
    var appLog       : ((String) -> Void)?
    
    init(port: Int) {
        self.port = port
    }
    
    func log(string s: String) {
        if let lcb = appLog {
            lcb(s)
        }
        else {
            print(s)
        }
    }
    
    func close(_ fd:FileDescriptor) {
        print("close socket[\(fd)]")
        self.lockQueue.async { [unowned self] in
            _ = self.openSockets.removeValue(forKey: fd)
        }
    }
    
    
    func start() {
        listenSocket = PassiveSocketIPv4(address: sockaddr_in(port: port))
        if listenSocket == nil || !listenSocket!.isValid { // neat, eh? ;-)
            log(string: "ERROR: could not create socket ...")
            return
        }
        
        log(string: "Listen socket \(listenSocket)")
        
        let queue = DispatchQueue(label:"cn.leaves.socks.process.queue", qos:.utility,attributes:[.concurrent])
        
        // Note: capturing self here
        _ = listenSocket!.listen(queue: queue, backlog: 5) { newSock in
            
            self.log(string: "got new sock: \(newSock) nio=\(newSock.isNonBlocking)")
            newSock.isNonBlocking = true
            newSock.queue = queue
            self.lockQueue.async {
                // Note: we need to keep the socket around!!
                self.openSockets[newSock.fd] = newSock
            }
            
            _ = SocksHandler(socket: newSock, server: self)
            
            
        }
        
        log(string: "Started running listen socket \(listenSocket)")
    }
    
    func stop() {
        listenSocket?.close()
        listenSocket = nil
    }
    
    let welcomeText = "\r\n" +
        "  /----------------------------------------------------\\\r\n" +
        "  |     Welcome to the Always Right Institute!         |\r\n"  +
        "  |    I am an echo server with a zlight twist.        |\r\n"  +
        "  | Just type something and I'll shout it back at you. |\r\n"  +
        "  \\----------------------------------------------------/\r\n"  +
        "\r\nTalk to me Dave!\r\n" +
    "> "
    
    func send<T: TextOutputStream>(welcome sockI: T) {
        var sock = sockI // cannot use 'var' in parameters anymore?
        // Hm, how to use print(), this doesn't work for me:
        //   print(s, target: sock)
        // (just writes the socket as a value, likely a tuple)
        sock.write(welcomeText)
    }
    
    func handleIncomingData<T>(socket s: ActiveSocket<T>, expectedCount: Int) {
        // remove from openSockets if all has been read
        repeat {
            // FIXME: This currently continues to read garbage if I just close the
            //        Terminal which hosts telnet. Even with sigpipe off.
            let (count, block, errno) = s.read()
            
            if count < 0 && errno == EWOULDBLOCK {
                break
            }
            
            if count < 1 {
                log(string: "EOF \(socket) (err=\(errno))")
                s.close()
                return
            }
            
            logReceived(block: block, length: count)
            
            // maps the whole block. asyncWrite does not accept slices,
            // can we add this?
            // (should adopt sth like IndexedCollection<T>?)
            /* ptr has no map ;-) FIXME: add an extension 'mapWithCount'?
             let mblock = block.map({ $0 == 83 ? 90 : ($0 == 115 ? 122 : $0) })
             */
            var mblock = [CChar](repeating: 42, count: count + 1)
            for i in 0..<count {
                let c = block[i]
                mblock[i] = c == 83 ? 90 : (c == 115 ? 122 : c)
            }
            mblock[count] = 0
            
            _ = s.asyncWrite(buffer: mblock, length: count)
        } while (true)
        
        s.write("> ")
    }
    
    func logReceived(block b: UnsafePointer<CChar>, length: Int) {
        let k = String(validatingUTF8: b)
        var s = k ?? "Could not process result block \(b) length \(length)"
        
        // Hu, now this is funny. In b5 \r\n is one Character (but 2 unicodeScalars)
        let suffix = String(s.characters.suffix(2))
        if suffix == "\r\n" {
            let to = s.index(before: s.endIndex)
            s = s[s.startIndex..<to]
        }
        
        log(string: "read string: \(s)")
    }
    
    final let alwaysRight = "Yes, indeed!"
}

