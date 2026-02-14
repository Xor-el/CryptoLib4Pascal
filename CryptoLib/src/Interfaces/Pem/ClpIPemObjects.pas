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

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIAsn1Objects;

type
  IPemHeader = interface;
  IPemObject = interface;
  IPemObjectGenerator = interface;

  /// <summary>
  /// Interface for PEM header objects.
  /// </summary>
  IPemHeader = interface(IInterface)
    ['{ED7A5DF3-5307-427B-8B47-63820438FEF1}']

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

  /// <summary>
  /// Interface for PEM reader.
  /// </summary>
  IPemReader = interface(IInterface)
    ['{0139877B-ED23-46C7-BE39-E5010AC26507}']

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

  /// <summary>
  /// Interface for PEM parser.
  /// </summary>
  IPemParser = interface(IInterface)
    ['{8C91EC3F-A5D3-4714-8A3E-A68C381FF754}']

    /// <summary>
    /// Read a PEM object from the stream and return it as an ASN.1 sequence.
    /// </summary>
    /// <param name="AInStream">The input stream to read from</param>
    /// <returns>An ASN.1 sequence, or nil if no PEM object found</returns>
    function ReadPemObject(const AInStream: TStream): IAsn1Sequence;
  end;

implementation

end.
