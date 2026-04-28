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

unit ClpIPemObject;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPemHeader,
  ClpCryptoLibTypes;

type
  IPemObject = interface;
  IPemObjectGenerator = interface;

  /// <summary>
  /// Interface for PEM object generator.
  /// </summary>
  IPemObjectGenerator = interface(IInterface)
    ['{B2C3D4E5-F6A7-8901-BCDE-F23456789012}']

    /// <summary>
    /// Generate a PEM object.
    /// </summary>
    /// <returns>A PEM object</returns>
    function Generate(): IPemObject;
  end;

  /// <summary>
  /// Interface for PEM objects.
  /// </summary>
  IPemObject = interface(IPemObjectGenerator)
    ['{9D65BB7D-721A-48B4-963B-13DBA970705A}']

    function GetType: String;
    function GetHeaders: TCryptoLibGenericArray<IPemHeader>;
    function GetContent: TCryptoLibByteArray;

    /// <summary>
    /// Get the PEM object type.
    /// </summary>
    property &Type: String read GetType;
    /// <summary>
    /// Get the PEM headers.
    /// </summary>
    property Headers: TCryptoLibGenericArray<IPemHeader> read GetHeaders;
    /// <summary>
    /// Get the PEM content (decoded from base64).
    /// </summary>
    property Content: TCryptoLibByteArray read GetContent;
  end;

implementation

end.
