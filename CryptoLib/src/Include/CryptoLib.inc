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


{---------------------------- Compiler Family Switch --------------------------}
{$IFDEF FPC}
  {$I CryptoLibFPC.inc} // FPC-specific settings
{$ELSE}
  {$DEFINE DELPHI}
  {$I ../../CryptoLib/src/Include/CryptoLibDelphi.inc} // Delphi-specific settings
{$ENDIF}

{-------------------------- Common Compiler Settings --------------------------}
{$SCOPEDENUMS ON}
{$OVERFLOWCHECKS OFF}
{$RANGECHECKS OFF}
{$POINTERMATH ON}
{$WARNINGS OFF}
{$HINTS OFF}

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
