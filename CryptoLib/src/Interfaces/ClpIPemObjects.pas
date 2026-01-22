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

unit ClpIPemObjects;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes;

type
  IPemHeader = interface;
  IPemObject = interface;
  IPemObjectGenerator = interface;

  /// <summary>
  /// Interface for PEM header objects.
  /// </summary>
  IPemHeader = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

    function GetName: String;
    function GetValue: String;

    /// <summary>
    /// Get the header name.
    /// </summary>
    property Name: String read GetName;
    /// <summary>
    /// Get the header value.
    /// </summary>
    property Value: String read GetValue;

    /// <summary>
    /// Get hash code for this header.
    /// </summary>
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
    /// <summary>
    /// Check if this header equals another object.
    /// </summary>
    function Equals(const AObj: IPemHeader): Boolean;
    /// <summary>
    /// Get string representation of this header.
    /// </summary>
    function ToString(): String;
  end;

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
    ['{C3D4E5F6-A7B8-9012-CDEF-0123456789AB}']

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

  /// <summary>
  /// Interface for PEM reader.
  /// </summary>
  IPemReader = interface(IInterface)
    ['{D4E5F6A7-B8C9-0123-DEF0-123456789ABC}']

    function GetReader: TStream;

    /// <summary>
    /// Get the underlying stream reader.
    /// </summary>
    property Reader: TStream read GetReader;

    /// <summary>
    /// Read a PEM object from the stream.
    /// </summary>
    /// <returns>A PEM object, or nil if end of stream</returns>
    function ReadPemObject(): IPemObject;
  end;

  /// <summary>
  /// Interface for PEM writer.
  /// </summary>
  IPemWriter = interface(IInterface)
    ['{E5F6A7B8-C9D0-1234-EF01-23456789ABCD}']

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
