//
//  ViewController.swift
//  SecKeyEncryption
//
//  Created by Sean Lin on 2020/12/10.
//

import UIKit

class ViewController: UIViewController {
    let message = "this is a sensitive message"
    let unsignedMesssage = "this is a message required signing"
    let enclaveKeyTag = "mySecureEnclaveKeyTag"
    let customKeyTag = "my.keypair.tag"
    let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                 kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                 [.privateKeyUsage,.biometryAny],
                                                 nil)!
    lazy var signedPrivateKeyParam: [String: Any] = [kSecClass as String: kSecClassKey,
                                                     kSecAttrApplicationTag as String: enclaveKeyTag,
                                                     kSecReturnRef as String: true,
                                                     kSecAttrAccessControl as String: access]
    
    lazy var privateKeyAttributes: [NSObject: Any] = [kSecAttrCanDecrypt : true,
                                                      kSecAttrIsPermanent : true,
                                                      kSecAttrApplicationTag : customKeyTag,
                                                      kSecClass: kSecClassKey,
                                                      kSecReturnRef: true]
    override func viewDidLoad() {
        super.viewDidLoad()
        executeSigning()
        executeAsymmetricEncryption()
    }
    
    private func executeSigning() {
        guard let privateKey = createSignedKey(), let publicKey = SecKeyCopyPublicKey(privateKey) else {
            print("Public key generation error")
            return
        }

        guard let signedString = signMessage(privateKey: privateKey) else { return }
        let isSuccess = verifySignedMessageString(publicKey: publicKey, signedString: signedString)
        print("verify signed message: ", isSuccess ? "succcess" : "fail")
    }
    
    private func createSignedKey() -> SecKey?{
        //Creating the Access Control Object
        let attributes = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: signedPrivateKeyParam
        ] as CFDictionary
        
        var item: CFTypeRef?
        var key: SecKey?
        let status = SecItemCopyMatching(signedPrivateKeyParam as CFDictionary, &item)
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
            print("signed key query failed: ", status)
        }
        return key
    }
    
    private func signMessage(privateKey: SecKey) -> String? {
        guard let messageData = unsignedMesssage.data(using: String.Encoding.utf8) else {
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
        guard let messageData = unsignedMesssage.data(using: String.Encoding.utf8) else {
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
        var item: CFTypeRef?
        var key: SecKey?
        let status = SecItemCopyMatching(privateKeyAttributes as CFDictionary, &item)
        if status == errSecSuccess {
            key = (item as! SecKey)
            guard let privateKey = key, let publicKey = SecKeyCopyPublicKey(privateKey) else { return }
            encryptDecryptMessage(publicKey: publicKey, privateKey: privateKey)
            deleteKey(query: privateKeyAttributes as CFDictionary)
        } else if status == errSecItemNotFound {
            let (publicKeySec, privateKeySec) = generateSecKeyPair()
            guard let publicKey = publicKeySec, let privateKey = privateKeySec else {
                print("invalid encryption key pair")
                return
            }
            encryptDecryptMessage(publicKey: publicKey, privateKey: privateKey)
        } else {
            print("encryption key query failed: ", status)
        }
    }
    
    private func encryptDecryptMessage(publicKey: SecKey, privateKey: SecKey) {
        if let encryptedMessage = encryptMessage(publicKey: publicKey) {
            print("encrypted msg: ", encryptedMessage)
            if let decryptedMessage = decryptMessage(privateKey: privateKey, encryptedMessage: encryptedMessage) {
                if decryptedMessage == message {
                    print("decrypt successfully, message: ", decryptedMessage)
                } else {
                    print("decrypt failed, message: ", decryptedMessage)
                }
            }
        }
    }
    
    private func encryptMessage(publicKey: SecKey) -> String? {
        guard let messageData = message.data(using: String.Encoding.utf8), let encryptData = SecKeyCreateEncryptedData(
                    publicKey,
                    SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                    messageData as CFData,
                    nil)
        else {
            print("Encryption message  error")
            return nil
        }
        
        let encryptedMsg = (encryptData as Data).base64EncodedString()
        print(encryptedMsg)
        return encryptedMsg
    }
    
    private func decryptMessage(privateKey: SecKey, encryptedMessage: String) -> String? {
        guard let encryptMessageData = Data(base64Encoded: encryptedMessage), let decryptData = SecKeyCreateDecryptedData(
                privateKey,
                SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                encryptMessageData as CFData,
                nil) else {
            print("Decryption message Error")
            return nil
        }
        
        guard let decryptedMessage = String(data: decryptData as Data, encoding: String.Encoding.utf8) else {
            print("Error retrieving decrypted string")
            return nil
        }
        return decryptedMessage
    }
    
    private func generateSecKeyPair() -> (publicKey: SecKey?, privateKey: SecKey?) {
        var publicKeySec, privateKeySec: SecKey?
        //Generating both the public and private keys via the SecGeneratePair APIs.
        let attributes = [  kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                            kSecAttrKeySizeInBits as String: 256,
                            kSecPrivateKeyAttrs as String: privateKeyAttributes,
                        ] as CFDictionary
        let status = SecKeyGeneratePair(attributes, &publicKeySec, &privateKeySec)
        if status < 0 {
            print("generate sec key pair error: ", status)
            return (nil, nil)
        } else {
            print("generate sec key pair successfully; pub: \(String(describing: publicKeySec)), private: \(String(describing: privateKeySec))")
            return (publicKeySec, privateKeySec)
        }
    }
    
    private func deleteKey(query: CFDictionary) {
        let delStatus = SecItemDelete(query)
        if delStatus == errSecSuccess {
           print("deleted key")
        } else {
            print("There was a problem deleting the key")
        }
    }
}

