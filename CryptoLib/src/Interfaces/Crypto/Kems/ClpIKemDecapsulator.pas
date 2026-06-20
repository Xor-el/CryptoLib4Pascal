{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIKemDecapsulator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  IKemDecapsulator = interface(IInterface)

    ['{C5D0E6F3-4A7B-6C8D-BE2F-3A4B5C6D7E8F}']

    procedure Init(const AParameters: ICipherParameters);

    function GetEncapsulationLength: Int32;
    function GetSecretLength: Int32;

    procedure Decapsulate(const AEncBuf: TCryptoLibByteArray; AEncOff, AEncLen: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff, ASecLen: Int32);

    property EncapsulationLength: Int32 read GetEncapsulationLength;
    property SecretLength: Int32 read GetSecretLength;

  end;

implementation

end.
