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

unit ClpCollectionUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  Classes,
  ClpAsn1Encodable,
  ClpIProxiedInterface;

type
  TCollectionUtilities = class sealed(TObject)

  public

    class function ToStructuredString(c: TEnumerable<IAsn1Encodable>)
      : String; static;

  end;

implementation

{ TCollectionUtilities }

class function TCollectionUtilities.ToStructuredString
  (c: TEnumerable<IAsn1Encodable>): String;
var
  e: TEnumerator<IAsn1Encodable>;
  sl: TStringList;
begin

  sl := TStringList.Create();
  sl.LineBreak := '';
  try
    sl.Add('[');
    e := c.GetEnumerator;
    if (e.MoveNext()) then
    begin
      sl.Add((e.Current as TAsn1Encodable).ClassName);

      while (e.MoveNext()) do
      begin
        sl.Add(', ');
        sl.Add((e.Current as TAsn1Encodable).ClassName);
      end;
    end;

    sl.Add(']');
    result := sl.Text;
  finally
    sl.Free;
  end;

end;

end.
