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

unit ClpIPemWriter;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIPemObjects;

type
  /// <summary>
  /// Interface for PEM writer.
  /// </summary>
  IPemWriter = interface(IInterface)
    ['{E534B37C-C6B0-4066-9AB9-758BDAD3C3A0}']

    function GetWriter: TStream;

    /// <summary>
    /// Get the underlying stream writer.
    /// </summary>
    property Writer: TStream read GetWriter;

    /// <summary>
    /// Get the estimated output size for a PEM object.
    /// </summary>
    /// <param name="AObj">The PEM object</param>
    /// <returns>Estimated size in bytes</returns>
    function GetOutputSize(const AObj: IPemObject): Int32;

    /// <summary>
    /// Write a PEM object to the stream.
    /// </summary>
    /// <param name="AObjGen">The PEM object generator</param>
    procedure WriteObject(const AObjGen: IPemObjectGenerator);
  end;

implementation

end.
