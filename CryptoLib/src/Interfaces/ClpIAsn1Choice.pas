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

unit ClpIAsn1Choice;

{$I ..\Include\CryptoLib.inc}

interface

type
  /// **
  // * Marker interface for CHOICE objects - if you implement this in a roll-your-own
  // * object, any attempt to tag the object implicitly will convert the tag to an
  // * explicit one as the encoding rules require.
  // * <p>
  // * If you use this interface your class should also implement the GetInstance
  // * pattern which takes a tag object and the tagging mode used.
  // * </p>
  // */
  IAsn1Choice = interface(IInterface)
    // marker interface
    ['{9C12BE01-9579-48F2-A5B0-4FA5DD807B32}']
  end;

implementation

end.
