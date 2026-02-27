{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpAsn1DigestFactory;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIDigestFactory,
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIDigest,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Objects,
  ClpDigestUtilities,
  ClpDefaultDigestCalculator;

type
  /// <summary>
  /// Digest factory for ASN.1 based operations.
  /// </summary>
  TAsn1DigestFactory = class sealed(TInterfacedObject, IDigestFactory)

  strict private
  var
    FDigest: IDigest;
    FOid: IDerObjectIdentifier;

  public
    class function Get(const AOid: IDerObjectIdentifier): IDigestFactory; overload; static;
    class function Get(const AMechanism: String): IDigestFactory; overload; static;

    constructor Create(const ADigest: IDigest; const AOid: IDerObjectIdentifier);

    function GetAlgorithmDetails: IAlgorithmIdentifier;
    function GetDigestLength: Int32;
    function CreateCalculator: IStreamCalculator<IBlockResult>;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
    property DigestLength: Int32 read GetDigestLength;
  end;

implementation

{ TAsn1DigestFactory }

class function TAsn1DigestFactory.Get(const AOid: IDerObjectIdentifier): IDigestFactory;
var
  LDigest: IDigest;
begin
  LDigest := TDigestUtilities.GetDigest(AOid);
  Result := TAsn1DigestFactory.Create(LDigest, AOid);
end;

class function TAsn1DigestFactory.Get(const AMechanism: String): IDigestFactory;
begin
  Result := Get(TDigestUtilities.GetObjectIdentifier(AMechanism));
end;

constructor TAsn1DigestFactory.Create(const ADigest: IDigest; const AOid: IDerObjectIdentifier);
begin
  inherited Create();
  FDigest := ADigest;
  FOid := AOid;
end;

function TAsn1DigestFactory.GetAlgorithmDetails: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(FOid);
end;

function TAsn1DigestFactory.GetDigestLength: Int32;
begin
  Result := FDigest.GetDigestSize();
end;

function TAsn1DigestFactory.CreateCalculator: IStreamCalculator<IBlockResult>;
begin
  Result := TDefaultDigestCalculator.Create(FDigest);
end;

end.
