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

unit ClpIFilterStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes;

type
  IFilterStream = interface(IInterface)
    ['{00DF43F6-55BB-4A90-AEE7-1C6D956E144A}']

    function QueryInterface({$IFDEF FPC}constref {$ELSE}const
{$ENDIF FPC} IID: TGUID; out Obj): HResult;
{$IF DEFINED(MSWINDOWS) OR DEFINED(DELPHI)} stdcall
{$ELSE} cdecl {$IFEND};
    function _AddRef: Integer; {$IF DEFINED(MSWINDOWS) OR DEFINED(DELPHI)} stdcall {$ELSE} cdecl
{$IFEND};
    function _Release: Integer; {$IF DEFINED(MSWINDOWS) OR DEFINED(DELPHI)} stdcall {$ELSE} cdecl
{$IFEND};

    function GetSize: Int64;
    function GetPosition: Int64;
    procedure SetPosition(const Value: Int64);

    property Size: Int64 read GetSize;
    property Position: Int64 read GetPosition write SetPosition;

    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
    function Read(var Buffer; Count: LongInt): LongInt;
    function Write(const Buffer; Count: LongInt): LongInt;
    function ReadByte(): Int32;
    procedure WriteByte(Value: Byte);

  end;

implementation

end.
