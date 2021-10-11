{


VigerePlus (version 2.2) - simple 512 bit block CBC-mode encryption algorithm based on 2-round Vigenere cipher,
includes byte-by-byte block permutation and transformation, bit rotation and 4 mutating 512-bit session keys.

Written by Alexander Myasnikov, Kolchugino, Vladimir region, Russia

August, 2008

E-Mail: darksoftware@ya.ru

Web: www.darksoftware.narod.ru

Freeware, open source, free for any usage, not patented

This is only idea, working idea. There are some bugs? Code is slow and not optimized.


}



unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,crc32, ComCtrls, StdCtrls, vg22, math;

type
  TForm1 = class(TForm)
    Button1: TButton;
    pg: TProgressBar;
    key: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Button2: TButton;
    Label3: TLabel;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }

  end;

var
  Form1: TForm1;

implementation

uses DCPsha512, DCPhaval;

{$R *.dfm}

function FileSizeByName(const AFilename: string): int64;
begin
  with TFileStream.Create(AFilename, fmOpenRead or fmShareDenyNone) do
    try
      Result := Size;
    finally
      Free;
      end;
end;   

procedure pproc(data: integer);
begin
form1.pg.Position:=form1.pg.Position+data
end;


procedure TForm1.Button1Click(Sender: TObject);
var crc1,crc2: cardinal;
begin

crc1:=filecrc32(extractfilepath(application.ExeName)+'test.txt');
pg.Max:=FileSizeByName(extractfilepath(application.ExeName)+'test.txt');
pg.Position:=0;
pg.Min:=0;
vgcrypt22(extractfilepath(application.ExeName)+'test.txt',extractfilepath(application.ExeName)+'test.enc',key.text,1,@pproc);
pg.Max:=FileSizeByName(extractfilepath(application.ExeName)+'test.txt');
pg.Position:=0;
pg.Min:=0;
vgcrypt22(extractfilepath(application.ExeName)+'test.enc',extractfilepath(application.ExeName)+'test.dec',key.text,0,@pproc);
crc2:=filecrc32(extractfilepath(application.ExeName)+'test.dec');
if crc1=crc2 then showmessage('All is fine!') else showmessage('File not decrypted!')
end;

procedure TForm1.Button2Click(Sender: TObject);
var i: integer;
begin
key.Text:='';
for i:=0 to 30 do begin
key.Text:=key.Text+Char(randomrange(byte('!'),byte('~')));
end;
end;

end.
