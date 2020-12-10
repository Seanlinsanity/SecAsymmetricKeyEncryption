//
//  ViewController.swift
//  SecKeyEncryption
//
//  Created by Sean Lin on 2020/12/10.
//

import UIKit

class ViewController: UIViewController {
    let message = "this is a sensitive message"
    private var publicKeySec, privateKeySec: SecKey?

    override func viewDidLoad() {
        super.viewDidLoad()
        (publicKeySec, privateKeySec) = generateSecKeyPair()
        guard let publicKey = publicKeySec, let privateKey = privateKeySec else {
            print("invalid key pair")
            return
        }

        if let encryptedMessage = encryptMessage(key: publicKey) {
            if let decryptedMessage = decryptMessage(key: privateKey, encryptedMessage: encryptedMessage) {
                if decryptedMessage == message {
                    print("decrypt successfully, message: ", decryptedMessage)
                } else {
                    print("decrypt failed, message: ", decryptedMessage)
                }
            }
        }
    }
    
    private func encryptMessage(key: SecKey) -> String? {
        guard let messageData = message.data(using: String.Encoding.utf8), let encryptData = SecKeyCreateEncryptedData(
                    key,
                    SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                    messageData as CFData,
                    nil)
        else {
            print("Encryption Error")
            return nil
        }
        
        return (encryptData as Data).base64EncodedString()
    }
    
    private func decryptMessage(key: SecKey, encryptedMessage: String) -> String? {
        guard let encryptMessageData = Data(base64Encoded: encryptedMessage), let decryptData = SecKeyCreateDecryptedData(
                key,
                SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                encryptMessageData as CFData,
                nil) else {
            print("Decryption Error")
            return nil
        }
        
        guard let decryptedMessage = String(data: decryptData as Data, encoding: String.Encoding.utf8) else {
            print("Error retrieving string")
            return nil
        }
        return decryptedMessage
    }
    
    private func generateSecKeyPair() -> (publicKey: SecKey?, privateKey: SecKey?){
        var publicKeySec, privateKeySec: SecKey?
        //Generating both the public and private keys via the SecGeneratePair APIs.
        let privateKeyTag = "my.private.key.tag".data(using: .utf8)!
        let privateKeyParams: [String: Any] = [
        kSecAttrCanDecrypt as String: true,
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: privateKeyTag]


        let attributes =
        [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String:
        privateKeyParams] as CFDictionary
        let status = SecKeyGeneratePair(attributes, &publicKeySec, &privateKeySec)
        if status < 0 {
            print("generate sec key pair error: ", status)
            return (nil, nil)
        } else {
            print("generate sec key pair successfully; pub: \(String(describing: publicKeySec)), private: \(String(describing: privateKeySec))")
            return (publicKeySec, privateKeySec)
        }
    }

}

