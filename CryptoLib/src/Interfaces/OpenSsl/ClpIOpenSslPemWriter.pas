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

unit ClpIOpenSslPemWriter;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Rtti,
  ClpIPemWriter,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for OpenSSL PEM writer. Write any supported object as PEM
  /// (type and encoding determined by TOpenSslMiscPemGenerator).
  /// </summary>
  IOpenSslPemWriter = interface(IPemWriter)
    ['{23403EC4-0046-4F52-8539-B5D49C0ED6E3}']
    procedure WriteObject(const AObj: TValue); overload;
    procedure WriteObject(const AObj: TValue; const AAlgorithm: String;
      const APassword: TCryptoLibCharArray; const ARandom: ISecureRandom); overload;
  end;

implementation

end.
