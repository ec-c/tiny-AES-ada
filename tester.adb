with Ada.Text_IO;
with Interfaces;

with AES;

procedure Tester is
   subtype u8 is Interfaces.Unsigned_8 range Interfaces.Unsigned_8'Range;
   type Bytes is array (Positive range <>) of aliased u8;
begin
   Ada.Text_IO.Put_Line ("Hello AES!");
end Tester;
