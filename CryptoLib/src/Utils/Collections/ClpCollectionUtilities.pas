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

    class function ToStructuredString(c: TList<IAsn1Encodable>): String; static;

  end;

implementation

{ TCollectionUtilities }

class function TCollectionUtilities.ToStructuredString
  (c: TList<IAsn1Encodable>): String;
var
  sl: TStringList;
  idx: Int32;
begin

  sl := TStringList.Create();
  sl.LineBreak := '';
  try
    sl.Add('[');

    if (c.Count <> 0) then
    begin
      sl.Add((c[0] as TAsn1Encodable).ClassName);
      if c.Count > 1 then
      begin
        for idx := 1 to c.Count - 2 do
        begin
          sl.Add(', ');
          sl.Add((c[idx] as TAsn1Encodable).ClassName);
        end;
      end;
    end;

    sl.Add(']');
    result := sl.Text;
  finally
    sl.Free;
  end;

end;

end.
