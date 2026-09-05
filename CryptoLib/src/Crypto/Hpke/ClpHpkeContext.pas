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

unit ClpHpkeContext;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpArrayUtilities,
  ClpIHpkeAead,
  ClpIHpkeKdf,
  ClpIHpkeContext,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Recipient-side HPKE context. Seal / Open advance an internal AEAD
  /// sequence number; Export derives auxiliary secrets deterministically.
  /// </summary>
  THpkeContext = class(TInterfacedObject, IHpkeContext)

  strict protected
  var
    FAead: IHpkeAead;
    FKdf: IHpkeKdf;
    FExporterSecret, FSuiteId: TCryptoLibByteArray;

  public
    constructor Create(const AAead: IHpkeAead; const AKdf: IHpkeKdf;
      const AExporterSecret, ASuiteId: TCryptoLibByteArray);

    destructor Destroy(); override;

    function Seal(const AAad, APt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Seal(const AAad, APt: TCryptoLibByteArray; APtOff, APtLen: Int32)
      : TCryptoLibByteArray; overload;

    function Open(const AAad, ACt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Open(const AAad, ACt: TCryptoLibByteArray; ACtOff, ACtLen: Int32)
      : TCryptoLibByteArray; overload;

    function Export(const AExporterContext: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;

    function Extract(const ASalt, AIkm: TCryptoLibByteArray)
      : TCryptoLibByteArray;

    function Expand(const APrk, AInfo: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;
  end;

  /// <summary>
  /// Sender-side HPKE context, additionally carrying the KEM encapsulation.
  /// </summary>
  THpkeContextWithEncapsulation = class sealed(THpkeContext,
    IHpkeContextWithEncapsulation)

  strict private
  var
    FEncapsulation: TCryptoLibByteArray;

  public
    constructor Create(const AAead: IHpkeAead; const AKdf: IHpkeKdf;
      const AExporterSecret, ASuiteId, AEncapsulation: TCryptoLibByteArray);

    function GetEncapsulation(): TCryptoLibByteArray;
  end;

implementation

{ THpkeContext }

constructor THpkeContext.Create(const AAead: IHpkeAead; const AKdf: IHpkeKdf;
  const AExporterSecret, ASuiteId: TCryptoLibByteArray);
begin
  inherited Create();
  FAead := AAead;
  FKdf := AKdf;
  FExporterSecret := AExporterSecret;
  FSuiteId := ASuiteId;
end;

destructor THpkeContext.Destroy;
begin
  // wipe the exporter secret held for the context lifetime
  TArrayUtilities.Fill(FExporterSecret, 0, System.Length(FExporterSecret),
    Byte(0));
  inherited Destroy();
end;

function THpkeContext.Seal(const AAad, APt: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := Seal(AAad, APt, 0, System.Length(APt));
end;

function THpkeContext.Seal(const AAad, APt: TCryptoLibByteArray;
  APtOff, APtLen: Int32): TCryptoLibByteArray;
begin
  Result := FAead.Seal(AAad, APt, APtOff, APtLen);
end;

function THpkeContext.Open(const AAad, ACt: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := Open(AAad, ACt, 0, System.Length(ACt));
end;

function THpkeContext.Open(const AAad, ACt: TCryptoLibByteArray;
  ACtOff, ACtLen: Int32): TCryptoLibByteArray;
begin
  Result := FAead.Open(AAad, ACt, ACtOff, ACtLen);
end;

function THpkeContext.Export(const AExporterContext: TCryptoLibByteArray;
  AL: Int32): TCryptoLibByteArray;
begin
  Result := FKdf.LabeledExpand(FExporterSecret, FSuiteId, 'sec',
    AExporterContext, AL);
end;

function THpkeContext.Extract(const ASalt, AIkm: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := FKdf.Extract(ASalt, AIkm);
end;

function THpkeContext.Expand(const APrk, AInfo: TCryptoLibByteArray; AL: Int32)
  : TCryptoLibByteArray;
begin
  Result := FKdf.Expand(APrk, AInfo, AL);
end;

{ THpkeContextWithEncapsulation }

constructor THpkeContextWithEncapsulation.Create(const AAead: IHpkeAead;
  const AKdf: IHpkeKdf;
  const AExporterSecret, ASuiteId, AEncapsulation: TCryptoLibByteArray);
begin
  inherited Create(AAead, AKdf, AExporterSecret, ASuiteId);
  FEncapsulation := AEncapsulation;
end;

function THpkeContextWithEncapsulation.GetEncapsulation: TCryptoLibByteArray;
begin
  Result := System.Copy(FEncapsulation);
end;

end.
