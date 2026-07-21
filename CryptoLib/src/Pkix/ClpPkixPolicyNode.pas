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

unit ClpPkixPolicyNode;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIPkixTypes,
  ClpIX509Asn1Objects,
  ClpWeakRef,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A node of the RFC 5280 6.1 valid policy tree.
  /// </summary>
  TPkixPolicyNode = class(TInterfacedObject, IPkixPolicyNode)

  strict private
  var
    FChildren: TList<IPkixPolicyNode>;
    FDepth: Int32;
    FExpectedPolicies: TCryptoLibStringArray;
    // weak: children are owned by their parent, so a strong link both ways would leak the tree
    FParent: TWeakRef<IPkixPolicyNode>;
    FPolicyQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
    FValidPolicy: String;
    FCritical: Boolean;

  strict protected
    function GetDepth: Int32;
    function GetChildren: TCryptoLibGenericArray<IPkixPolicyNode>;
    function GetHasChildren: Boolean;
    function GetIsCritical: Boolean;
    procedure SetIsCritical(AValue: Boolean);
    function GetPolicyQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
    function GetValidPolicy: String;
    function GetExpectedPolicies: TCryptoLibStringArray;
    procedure SetExpectedPolicies(const AValue: TCryptoLibStringArray);
    function GetParent: IPkixPolicyNode;
    procedure SetParent(const AValue: IPkixPolicyNode);

  public
    constructor Create(const AChildren: TCryptoLibGenericArray<IPkixPolicyNode>; ADepth: Int32;
      const AExpectedPolicies: TCryptoLibStringArray; const AParent: IPkixPolicyNode;
      const APolicyQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
      const AValidPolicy: String; ACritical: Boolean);
    destructor Destroy; override;

    procedure AddChild(const AChild: IPkixPolicyNode);
    procedure RemoveChild(const AChild: IPkixPolicyNode);
    function HasExpectedPolicy(const APolicy: String): Boolean;
    function Copy: IPkixPolicyNode;

    function ToString: String; overload; override;
    function ToString(const AIndent: String): String; reintroduce; overload;
  end;

implementation

{ TPkixPolicyNode }

constructor TPkixPolicyNode.Create(const AChildren: TCryptoLibGenericArray<IPkixPolicyNode>;
  ADepth: Int32; const AExpectedPolicies: TCryptoLibStringArray; const AParent: IPkixPolicyNode;
  const APolicyQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
  const AValidPolicy: String; ACritical: Boolean);
var
  LIdx: Int32;
begin
  inherited Create();
  FChildren := TList<IPkixPolicyNode>.Create();
  for LIdx := 0 to System.High(AChildren) do
  begin
    FChildren.Add(AChildren[LIdx]);
  end;
  FDepth := ADepth;
  FExpectedPolicies := System.Copy(AExpectedPolicies);
  FParent.Assign(AParent);
  FPolicyQualifiers := System.Copy(APolicyQualifiers);
  FValidPolicy := AValidPolicy;
  FCritical := ACritical;
end;

destructor TPkixPolicyNode.Destroy;
begin
  FChildren.Free;
  inherited Destroy;
end;

function TPkixPolicyNode.GetDepth: Int32;
begin
  Result := FDepth;
end;

function TPkixPolicyNode.GetChildren: TCryptoLibGenericArray<IPkixPolicyNode>;
var
  LIdx: Int32;
begin
  System.SetLength(Result, FChildren.Count);
  for LIdx := 0 to FChildren.Count - 1 do
  begin
    Result[LIdx] := FChildren[LIdx];
  end;
end;

function TPkixPolicyNode.GetHasChildren: Boolean;
begin
  Result := FChildren.Count <> 0;
end;

function TPkixPolicyNode.GetIsCritical: Boolean;
begin
  Result := FCritical;
end;

procedure TPkixPolicyNode.SetIsCritical(AValue: Boolean);
begin
  FCritical := AValue;
end;

function TPkixPolicyNode.GetPolicyQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
begin
  Result := System.Copy(FPolicyQualifiers);
end;

function TPkixPolicyNode.GetValidPolicy: String;
begin
  Result := FValidPolicy;
end;

function TPkixPolicyNode.GetExpectedPolicies: TCryptoLibStringArray;
begin
  Result := System.Copy(FExpectedPolicies);
end;

procedure TPkixPolicyNode.SetExpectedPolicies(const AValue: TCryptoLibStringArray);
begin
  FExpectedPolicies := System.Copy(AValue);
end;

function TPkixPolicyNode.GetParent: IPkixPolicyNode;
begin
  Result := FParent.Target;
end;

procedure TPkixPolicyNode.SetParent(const AValue: IPkixPolicyNode);
begin
  FParent.Assign(AValue);
end;

procedure TPkixPolicyNode.AddChild(const AChild: IPkixPolicyNode);
begin
  if AChild = nil then
    Exit;
  AChild.Parent := Self as IPkixPolicyNode;
  FChildren.Add(AChild);
end;

procedure TPkixPolicyNode.RemoveChild(const AChild: IPkixPolicyNode);
var
  LIdx: Int32;
begin
  for LIdx := 0 to FChildren.Count - 1 do
  begin
    if FChildren[LIdx] = AChild then
    begin
      // detach, so the removed subtree cannot be reached back through a stale parent
      FChildren[LIdx].Parent := nil;
      FChildren.Delete(LIdx);
      Exit;
    end;
  end;
end;

function TPkixPolicyNode.HasExpectedPolicy(const APolicy: String): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(FExpectedPolicies) do
  begin
    if FExpectedPolicies[LIdx] = APolicy then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

function TPkixPolicyNode.Copy: IPkixPolicyNode;
var
  LCopy: IPkixPolicyNode;
  LIdx: Int32;
begin
  LCopy := TPkixPolicyNode.Create(nil, FDepth, System.Copy(FExpectedPolicies), nil,
    System.Copy(FPolicyQualifiers), FValidPolicy, FCritical);

  for LIdx := 0 to FChildren.Count - 1 do
  begin
    LCopy.AddChild(FChildren[LIdx].Copy());
  end;

  Result := LCopy;
end;

function TPkixPolicyNode.ToString: String;
begin
  Result := ToString('');
end;

function TPkixPolicyNode.ToString(const AIndent: String): String;
var
  LBuilder: TStringBuilder;
  LIdx: Int32;
begin
  LBuilder := TStringBuilder.Create();
  try
    LBuilder.Append(AIndent);
    LBuilder.Append(FValidPolicy);
    LBuilder.AppendLine(' {');

    for LIdx := 0 to FChildren.Count - 1 do
    begin
      LBuilder.Append(FChildren[LIdx].ToString(AIndent + '    '));
    end;

    LBuilder.Append(AIndent);
    LBuilder.AppendLine('}');
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

end.
