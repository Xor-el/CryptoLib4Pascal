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

unit ClpBerSequenceGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpAsn1Tags,
  ClpBerGenerator,
  ClpIBerSequenceGenerator;

type
  TBerSequenceGenerator = class(TBerGenerator, IBerSequenceGenerator)

  public
    constructor Create(outStream: TStream); overload;
    constructor Create(outStream: TStream; tagNo: Int32;
      isExplicit: Boolean); overload;
  end;

implementation

{ TBerSequenceGenerator }

constructor TBerSequenceGenerator.Create(outStream: TStream);
begin
  Inherited Create(outStream);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.Sequence);
end;

constructor TBerSequenceGenerator.Create(outStream: TStream; tagNo: Int32;
  isExplicit: Boolean);
begin
  Inherited Create(outStream, tagNo, isExplicit);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.Sequence);
end;

end.
