# CryptoLib4Pascal
CryptoLib4Pascal is a Cryptographic Package for Delphi/FreePascal Compilers that provides at the moment support for creating, signing and verifying ECDSA Signatures using various curves and hashes.

**Supported Algorithms:**

    Supported Curves at the moment are secp256k1, sect283k1, secp384r1 and secp521r1.
    Supported signing algorithms are NONEwithECDSA, SHA-1withECDSA, SHA-224withECDSA, 
    SHA-256withECDSA, SHA-384withECDSA, SHA-512withECDSA and RIPEMD160withECDSA
    
   **Dependencies:**

    [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) >= v2.3
    For FreePascal v3.0.x [Generics.Collections](https://github.com/maciej-izak/generics.collections)

**Supported Compilers**
 
    FreePascal 3.0.0 and Above.
    
    Delphi 2010 and Above.

**Installing the Library.**

**Method One:**

 Use the Provided Packages in the "Packages" Folder.

**Method Two:**

 Add the Library Path and Sub Path to your Project Search Path.

**Usage Examples.**

    Check the "CryptoLib.Samples" folder and the Unit Tests.

 **Unit Tests.**

To Run Unit Tests,

**For FPC 3.0.0 and above**


    Simply compile and run "CryptoLib.Tests" project in "FreePascal.Tests" Folder.

**For Delphi 2010 and above**

   **Method One (Using DUnit Test Runner)**

     To Build and Run the Unit Tests For Delphi 10 Tokyo (should be similar for 
     other versions)
    
    1). Open Project Options of Unit Test (CryptoLib.Tests) in "Delphi.Tests" Folder.
    
    2). Change Target to All Configurations (Or "Base" In Older Delphi Versions.)
    
    3). In Output directory add ".\$(Platform)\$(Config)" without the quotes.
    
    4). In Search path add "$(BDS)\Source\DUnit\src" without the quotes.
    
    5). In Unit output directory add "." without the quotes.
    
    6). In Unit scope names (If Available), Delete "DUnitX" from the List.
    
    Press Ok and save, then build and run.
    
 **Method Two (Using TestInsight) (Preferred).**

    1). Download and Install TestInsight.
    
    2). Open Project Options of Unit Test (CryptoLib.Tests.TestInsight) in "Delphi.Tests" 
        Folder. 

    3). Change Target to All Configurations (Or "Base" In Older Delphi Versions.)

    4). In Unit scope names (If Available), Delete "DUnitX" from the List.

    5). To Use TestInsight, right-click on the project, then select 
		"Enable for TestInsight" or "TestInsight Project".
        Save Project then Build and Run Test Project through TestInsight. 
        
  **Acknowledgements**
 
Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring the development of this library.

**License**

This "Software" is Licensed Under  **`MIT License (MIT)`** .

