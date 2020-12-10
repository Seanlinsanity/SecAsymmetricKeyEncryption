//
//  ViewController.swift
//  SecKeyEncryption
//
//  Created by Sean Lin on 2020/12/10.
//

import UIKit

class ViewController: UIViewController {
    let message = "this is a sensitive message"
    let signedMesssag = "this is a signed message"
    let enclaveKeyTag = "mySecureEnclaveKeyTag"
    let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                 kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                 [.privateKeyUsage,.biometryAny],
                                                 nil)!
    lazy var secEnclaveTag = enclaveKeyTag.data(using: .utf8)! //1
    lazy var privateKeyParams: [String: AnyObject] = [
        kSecAttrIsPermanent as String: true as AnyObject,
        kSecAttrApplicationTag as String: secEnclaveTag as AnyObject,
        kSecAttrAccessControl as String: access
    ]
    lazy var attributes = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: privateKeyParams
    ] as CFDictionary
    
    lazy var getQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: enclaveKeyTag,
                                   kSecReturnRef as String: true,
                                   kSecAttrAccessControl as String: access
                                ]
    
    private var publicKeySec, privateKeySec: SecKey?

    override func viewDidLoad() {
        super.viewDidLoad()
        executeSignMsg()
        executeAsymmetricEncryption()
    }
    
    private func executeSignMsg() {
        guard let privateKey = createSignedKey(), let publicKey = SecKeyCopyPublicKey(privateKey) else {
            print("Public key generation error")
            return
        }

        guard let signedString = signMessage(privateKey: privateKey) else { return }
        let isSuccess = verifySignedMessageString(publicKey: publicKey, signedString: signedString)
        print("verify signed message: ", isSuccess)
    }
    
    private func createSignedKey() -> SecKey?{
        //Creating the Access Control Object
        var item: CFTypeRef?
        var key: SecKey?
        let status = SecItemCopyMatching(getQuery as CFDictionary, &item)
        if status == errSecSuccess {
            key = (item as! SecKey)
        } else if status == errSecItemNotFound {
            var error: Unmanaged<CFError>?
            guard let newKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                print(error!.takeRetainedValue() as Error)
                return nil
            }
            key = newKey
        } else {
            print("key query failed")
        }
        return key
    }
    
    private func signMessage(privateKey: SecKey) -> String? {
        guard let messageData = signedMesssag.data(using: String.Encoding.utf8) else {
            print("Invalid message to sign.")
            return nil
        }
        
        var signError: Unmanaged<CFError>?
        guard let signData = SecKeyCreateSignature(
                privateKey,
                SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                messageData as CFData,
                &signError) else {
            print("Signing Error: ", signError ?? "empty error")
            return nil
        }
        let signedData = signData as Data
        let signedString = signedData.base64EncodedString(options: [])
        print("Signed String", signedString)
        return signedString
    }
    
    private func verifySignedMessageString(publicKey:SecKey, signedString: String) -> Bool {
        guard let messageData = signedMesssag.data(using: String.Encoding.utf8) else {
            print("Invalid message to sign.")
            return false
        }
        guard let signedMessageData = Data(base64Encoded: signedString) else {
            print("Invalid message to verify.")
            return false
        }
        let verify = SecKeyVerifySignature(
            publicKey,
            SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
            messageData as CFData,
            signedMessageData as CFData,
        nil)
        return verify
    }
    
    private func executeAsymmetricEncryption() {
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
    
    private func deleteKey() {
        let delStatus = SecItemDelete(getQuery as CFDictionary)
        if delStatus == errSecSuccess {
           print("deleted key")
        } else {
            print("There was a problem deleting the key")
        }
    }
}

