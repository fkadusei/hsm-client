sequenceDiagram
    participant App
    participant PKCS11 as PKCS#11 Library
    participant HSM
    participant Token as Token/Partition


    App->>PKCS11: Load library (.so / .dll)
    App->>PKCS11: C_Initialize()
    App->>PKCS11: C_GetSlotList()
    App->>PKCS11: C_OpenSession(slot)
    App->>PKCS11: C_Login(USER_PIN)
    App->>PKCS11: C_GenerateKeyPair()
    PKCS11->>HSM: Create key inside token
    App->>PKCS11: C_Sign(data)
    PKCS11->>HSM: Perform crypto operation
    HSM-->>PKCS11: Signature
    PKCS11-->>App: Signature returned
