//
//  SocksConnection.swift
//  coconut
//
//  Created by leaves chen on 2017/1/17.
//
//

import Dispatch

#if os(Linux) // for sockaddr_in
    import Glibc
#else
    import Darwin
#endif
import SwiftSockets

class SocksHandler {
    struct SOCKS {
        static let version: UInt8 = 5
        static let reserved: UInt8 = 0
    }
    
    static let replyTag = 100
    
    enum Phase: Int {
        case methodSelection = 10
        case methodSelectionReply
        case request
        case requestReply
        
        var tag: Int {
            get {
                return self.rawValue
            }
        }
    }
    
    /*
     +----+----------+----------+
     |VER | NMETHODS | METHODS  |
     +----+----------+----------+
     | 1  |    1     | 1 to 255 |
     +----+----------+----------+
     */
    struct MethodSelection {
        let numberOfAuthenticationMethods: UInt8
        let authenticationMethods: [AuthenticationMethod]
        
        init(bytes: [UInt8]) throws {
            
            guard bytes.count >= 3 else {
                throw SocketError.wrongNumberOfAuthenticationMethods
            }
            
            guard bytes[0] == SOCKS.version else {
                throw SocketError.invalidSOCKSVersion
            }
            
            numberOfAuthenticationMethods = bytes[1]
            
            guard bytes.count == 1 + 1 + Int(numberOfAuthenticationMethods) else {
                throw SocketError.wrongNumberOfAuthenticationMethods
            }
            
            authenticationMethods = try bytes[2...(bytes.count - 1)].map() {
                guard let method = AuthenticationMethod(rawValue: $0) else {
                    throw SocketError.notSupportedAuthenticationMethod
                }
                return method
            }
        }
        
        var data: [UInt8]? {
            get {
                var bytes = [UInt8]()
                
                bytes.append(SOCKS.version)
                bytes.append(numberOfAuthenticationMethods)
                bytes.append(contentsOf: authenticationMethods.map() { $0.rawValue })
                
                let data = bytes
                return data
            }
        }
    }
    
    /*
     +----+--------+
     |VER | METHOD |
     +----+--------+
     | 1  |   1    |
     +----+--------+
     */
    struct MethodSelectionReply {
        let method: AuthenticationMethod
        
        init(data: [UInt8]) throws {
            throw SocketError.notImplemented
        }
        
        init(method: AuthenticationMethod) {
            self.method = method
        }
        
        var data: [UInt8]? {
            get {
                let bytes = [SOCKS.version, method.rawValue]
                return bytes
            }
        }
    }
    
    /*
     +----+-----+-------+------+----------+----------+
     |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
     +----+-----+-------+------+----------+----------+
     | 1  |  1  | X'00' |  1   | Variable |    2     |
     +----+-----+-------+------+----------+----------+
     o  VER    protocol version: X'05'
     o  CMD
     o  CONNECT X'01'
     o  BIND X'02'
     o  UDP ASSOCIATE X'03'
     o  RSV    RESERVED
     o  ATYP   address type of following address
     o  IP V4 address: X'01'
     o  DOMAINNAME: X'03'
     o  IP V6 address: X'04'
     o  DST.ADDR       desired destination address
     o  DST.PORT desired destination port in network octet order
     */
    struct Request {
        enum Command: UInt8 {
            case connect = 0x01
            case bind
            case udpAssociate
        }
        
        let command: Command
        let addressType: AddressType
        let targetHost: String
        let targetPort: UInt16
        
        init(bytes: [UInt8]) throws {
            
            var offset = 0
            
            guard bytes[offset] == SOCKS.version else {
                throw SocketError.invalidSOCKSVersion
            }
            offset += 1
            
            guard let cmd = Command(rawValue: bytes[offset]) else {
                throw SocketError.invalidRequestCommand
            }
            offset += 1
            command = cmd
            
            // Reserved
            _ = bytes[offset]
            offset += 1
            
            guard let atyp = AddressType(rawValue: bytes[offset]) else {
                throw SocketError.invalidAddressType
            }
            offset += 1
            addressType = atyp
            
            switch addressType {
            case .domainName:
//                let domainNameLength = bytes[offset]
//                offset += 1
//                guard let domainName = String(bytes: bytes[offset..<(offset + Int(domainNameLength))], encoding: String.Encoding.ascii) else {
//                    throw SocketError.invalidDomainName
//                }
//                targetHost = domainName
//                offset += Int(domainNameLength)
                targetHost = ""
            case .ipv4:
                let a = bytes[offset]
                offset += 1
                let b = bytes[offset]
                offset += 1
                let c = bytes[offset]
                offset += 1
                let d = bytes[offset]
                offset += 1
                targetHost = "\(a).\(b).\(c).\(d)"
                break
            default:
                targetHost = ""
                break
            }
            targetPort = (UInt16(bytes[offset])<<8) + UInt16(bytes[offset+1])
        }
        
        var data: [UInt8]? {
            get {
                var bytes: [UInt8] = [SOCKS.version, command.rawValue, SOCKS.reserved, addressType.rawValue]
                
                switch addressType {
                case .domainName:
                    bytes.append(UInt8(targetHost.characters.count))
                    bytes.append(contentsOf: [UInt8](targetHost.utf8))
                    break
                case .ipv4:
                    let ns = targetHost.characters.split(separator: ".").map(String.init)
                    for n in ns {
                        bytes.append((UInt8(n))!)
                    }
                    break
                default:
                    break
                }
                bytes.append(UInt8(targetPort >> 8))
                bytes.append(UInt8(targetPort & 0x00ff))
                
                return bytes
            }
        }
    }
    
    /*
     o  X'00' NO AUTHENTICATION REQUIRED
     o  X'01' GSSAPI
     o  X'02' USERNAME/PASSWORD
     o  X'03' to X'7F' IANA ASSIGNED
     o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
     o  X'FF' NO ACCEPTABLE METHODS
     */
    enum AuthenticationMethod: UInt8 {
        case
        none = 0x00,
        gssapi,
        usernamePassword
    }
    
    enum AddressType: UInt8 {
        case ipv4 = 0x01
        case ipv6 = 0x04
        case domainName = 0x03
    }
    
    enum SocketError: Error {
        case invalidSOCKSVersion
        case unableToRetrieveNumberOfAuthenticationMethods
        case notSupportedAuthenticationMethod
        case supportedAuthenticationMethodNotFound
        case wrongNumberOfAuthenticationMethods
        case invalidRequestCommand
        case invalidHeaderFragment
        case invalidAddressType
        case invalidDomainLength
        case invalidDomainName
        case invalidPort
        case notImplemented
    }
    
    /*
     +----+-----+-------+------+----------+----------+
     |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
     +----+-----+-------+------+----------+----------+
     | 1  |  1  | X'00' |  1   | Variable |    2     |
     +----+-----+-------+------+----------+----------+
     */
    struct Reply {
        enum Field: UInt8 {
            case succeed = 0x00
            case generalSOCKSServerFailure
            case connectionNotAllowedByRuleset
            case networkUnreachable
            case connectionRefused
            case ttlExpired
            case commandNotSupported
            case addressTypeNotSupported
        }
        let field: Field
        let addressType: AddressType
        let address: String
        let port: UInt16
        
        init(data: [UInt8]) throws {
            throw SocketError.notImplemented
        }
        
        init(field: Field, addressType: AddressType, address: String, port: UInt16) {
            self.field = field
            self.addressType = addressType
            self.address = address
            self.port = port
        }
        
        var data: [UInt8]? {
            get {
                var bytes: [UInt8] = [SOCKS.version, field.rawValue, SOCKS.reserved]
                
                // If reply field is anything other than Succeed, just reply with
                // VER, REP, RSV
                guard field == .succeed else {
                    return bytes
                }
                
                bytes.append(addressType.rawValue)
                
                switch addressType {
                case .domainName:
                    bytes.append(UInt8(address.characters.count))
                    bytes.append(contentsOf: [UInt8](address.utf8))
                    break
                case .ipv4:
                    let ns = address.characters.split(separator: ".").map(String.init)
                    for n in ns {
                        bytes.append((UInt8(n))!)
                    }
                    break
                default:
                    break
                }
                
                bytes.append(UInt8(port >> 8))
                bytes.append(UInt8(port & 0x00ff))
                return bytes
            }
        }
        
        var tag: Int {
            get {
                switch field {
                case .succeed:
                    return SocksHandler.replyTag
                default:
                    return 0
                }
            }
        }
    }
    
    enum Step {
        case new
        case method
        case request
        case data
    }
    
    var server:Socks5Server
    var socket:ActiveSocket<sockaddr_in>
    var remoteSocket:ActiveSocket<sockaddr_in>?
    var methodSelection:MethodSelection?
    var step:Step
    
    init(socket:ActiveSocket<sockaddr_in>, server:Socks5Server){
        self.socket = socket
        self.server = server
        step = .new
        _ = socket.onRead{self.handleIncomingData(socket: $0, expectedCount: $1)}
            .onClose{(fd: FileDescriptor ) -> Void in
                server.close(fd)
                }
    }
    
    func handleIncomingData<T>(socket s: ActiveSocket<T>, expectedCount: Int){
        do{
            let (count, block, _) = s.read()
            if count < 1 {
                //TODO 读取数据失败，处理关闭socket流程
                print("close incoming")
                self.socket.close()
                self.remoteSocket!.close()
                self.remoteSocket = nil
                return
            }
            let _block = unsafeBitCast(block, to:UnsafePointer<UInt8>.self)
            switch step{
            case .new:
                try self.processMethodSelection(convert(count: count, data: _block))
                step = .request
                break
            case .request:
                try self.processRequest(convert(count: count, data: _block))
                break;
            case .data:
                self.processData(block, count)
                break
            default:
                socket.close()
                break
            }
        }catch{
            print("handle incoming failed. \(error)")
        }
    }
    func convert<T>(count: Int, data: UnsafePointer<T>) -> [T] {
        
        let buffer = UnsafeBufferPointer(start: data, count: count);
        return Array(buffer)
    }
    
    fileprivate func processMethodSelection(_ data: [UInt8]) throws {
        let methodSelection = try MethodSelection(bytes:[UInt8](data))
        guard methodSelection.authenticationMethods.contains(.none) else {
            throw SocketError.supportedAuthenticationMethodNotFound
        }
        self.methodSelection = methodSelection
        let reply = MethodSelectionReply(method: .none)
        _ = socket.asyncWrite(buffer: UnsafePointer(reply.data!), length: (reply.data?.count)!)
    }
    
    fileprivate func processRequest(_ data: [UInt8]) throws {
        let request = try Request(bytes: data)
        let remoteAddress = sockaddr_in(address: request.targetHost, port: Int(request.targetPort))
        //connect remote
        remoteSocket = ActiveSocket<sockaddr_in>()
        _ = remoteSocket!.onRead { s, _ in
            let (count, block, _) = s.read()
            if count < 1  {
                print("close remote")
                self.socket.close()
                self.remoteSocket!.close()
                self.remoteSocket = nil
                return
            }
            print("write to socket with \(count)")
            _ = self.socket.asyncWrite(buffer: block, length: count)
        }
        
        let ok = remoteSocket?.connect(remoteAddress) { s in
            print("connected remote \(remoteAddress.asString)")
            s.queue = self.socket.queue
            let reply = Reply(field: .succeed, addressType: request.addressType, address: request.targetHost, port: request.targetPort)
            step = .data
            _ = self.socket.asyncWrite(buffer: reply.data!)
        }
        if !ok! {
            remoteSocket!.close()
            remoteSocket = nil
        }
        
    }
    
    fileprivate func processData(_ block:UnsafePointer<CChar>, _ count:Int){
        print("write to remote with \(count)")
        _ = remoteSocket?.asyncWrite( buffer: block, length: count)
    }
    
    
}
