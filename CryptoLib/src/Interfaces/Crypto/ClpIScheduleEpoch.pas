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

unit ClpIScheduleEpoch;

{$I ..\..\Include\CryptoLib.inc}

interface

type
  /// <summary>
  ///   Exposes a monotonic "schedule generation" from a keyed cipher whose
  ///   key-derived state (round keys, and any pointer bound to them) is rebuilt
  ///   in place. A consumer that caches something derived from the schedule -
  ///   e.g. an accelerated kernel holding a raw pointer into the round-key
  ///   buffer - reads this once per use: an unequal value means the schedule was
  ///   rebuilt and every such cached handle is stale and must be re-acquired.
  ///   Distinct from a same-key reuse test: the epoch changes on every rebuild,
  ///   whether or not the key value differs.
  /// </summary>
  IScheduleEpoch = interface
    ['{7B2E4D19-3A6C-4F81-9D52-8E1A0C7B6F34}']

    /// <summary>Current schedule-rebuild generation. Unequal to a previously
    /// cached value =&gt; the schedule was rebuilt since; equal =&gt; the schedule
    /// (and anything bound to it) is unchanged.</summary>
    function GetScheduleEpoch: UInt32;
  end;

implementation

end.
