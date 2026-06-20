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

unit ClpIKemEncapsulator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  IKemEncapsulator = interface(IInterface)

    ['{B4C9D5E2-3F6A-5B7C-AD1E-2F3A4B5C6D7E}']

    procedure Init(const AParameters: ICipherParameters);

    function GetEncapsulationLength: Int32;
    function GetSecretLength: Int32;

    procedure Encapsulate(const AEncBuf: TCryptoLibByteArray; AEncOff, AEncLen: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff, ASecLen: Int32);

    property EncapsulationLength: Int32 read GetEncapsulationLength;
    property SecretLength: Int32 read GetSecretLength;

  end;

implementation

end.
