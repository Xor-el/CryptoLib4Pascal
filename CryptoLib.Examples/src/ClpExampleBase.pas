unit ClpExampleBase;

interface

uses
  ClpLogger;

type
  IExample = interface(IInterface)
    ['{EC8F2122-75DB-4F47-8007-B912D7001C8E}']
    procedure Run;
  end;

  TExampleBase = class(TInterfacedObject, IExample)
  public
    function Logger: ILogger;
    procedure Run; virtual; abstract;
  end;

implementation

function TExampleBase.Logger: ILogger;
begin
  Result := TClpLogger.GetDefaultLogger;
end;

end.
