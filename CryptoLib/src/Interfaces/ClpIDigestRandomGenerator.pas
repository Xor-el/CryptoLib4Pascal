{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIDigestRandomGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIRandomGenerator;

type

  IDigestRandomGenerator = interface(IRandomGenerator)
    ['{1D9AA8E6-1709-4121-8835-61A7F543FB54}']

    procedure AddSeedMaterial(inSeed: TCryptoLibByteArray); overload;
    procedure AddSeedMaterial(rSeed: Int64); overload;
    procedure NextBytes(bytes: TCryptoLibByteArray); overload;
    procedure NextBytes(bytes: TCryptoLibByteArray; start, len: Int32);
      overload;

  end;

implementation

end.
