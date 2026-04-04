{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIAeadCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  IAeadCipher = interface(IInterface)
    ['{0BAD818A-E363-4818-9FF9-75FDE537AE46}']

    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);

    procedure ProcessAadByte(AInput: Byte);
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32);

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;

    function GetMac(): TCryptoLibByteArray;

    function GetUpdateOutputSize(ALen: Int32): Int32;
    function GetOutputSize(ALen: Int32): Int32;

    procedure Reset();
  end;

implementation

end.
