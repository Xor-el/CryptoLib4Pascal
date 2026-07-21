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

unit ClpIStore;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Criterion used to pick objects out of an <see cref="IStore&lt;T&gt;" />.
  /// </summary>
  ISelector<T> = interface
    /// <summary>
    /// Return True if ACandidate is matched by this selector.
    /// </summary>
    function Match(const ACandidate: T): Boolean;
    /// <summary>
    /// Return an independent copy, so the original cannot be mutated through it.
    /// </summary>
    function Clone: ISelector<T>;
  end;

  /// <summary>
  /// A simple store of objects that can be queried with an <see cref="ISelector&lt;T&gt;" />.
  /// </summary>
  IStore<T> = interface
    /// <summary>
    /// Return the (possibly empty) set of stored objects matched by ASelector.
    /// A nil selector matches everything.
    /// </summary>
    function EnumerateMatches(const ASelector: ISelector<T>): TCryptoLibGenericArray<T>;
  end;

implementation

end.
