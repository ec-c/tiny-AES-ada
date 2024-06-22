with Ahven;

with AES;

package body Test_AES is
   use Ahven;

   overriding
   procedure Initialize (Test : in out Test_T) is
   begin
      Set_Name (Test, "AES");

      Ahven.Framework.Add_Test_Routine (Test, Test_AES128_Encrypt_CTR_1'Access,
         "AES128 Encrypt CTR 1");
   end Initialize;

   package AES128 is new AES
      (u8, Positive, Bytes, Interfaces.Shift_Left, Interfaces.Shift_Right);

   procedure Test_AES128_Encrypt_CTR_1 is
      Key : constant Bytes :=
         [16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
          16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#];
      Init_Vector : constant Bytes :=
         [16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
          16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#];
      Input : constant Bytes :=
         [16#00#, 16#00#, 16#01#, 16#01#, 16#03#, 16#03#, 16#07#, 16#07#,
          16#0f#, 16#0f#, 16#1f#, 16#1f#, 16#3f#, 16#3f#, 16#7f#, 16#7f#];
      Expected : constant Bytes :=
         [16#c7#, 16#d1#, 16#24#, 16#19#, 16#48#, 16#9e#, 16#3b#, 16#62#,
          16#33#, 16#a2#, 16#c5#, 16#a7#, 16#f4#, 16#56#, 16#31#, 16#72#];

      package AES128_CTR1 is new AES128.CTR (Init_Vector);
      Buf1 : AES128_CTR1.Buffer;
      Result : constant Bytes := Buf1.Xcrypt (Input);
   begin
      Assert (Result = Expected, "fail");
   end Test_AES128_Encrypt_CTR_1;

   procedure Test_AES128_Encrypt_CTR_2 is
      Key : constant Bytes :=
         [16#2b#, 16#7e#, 16#15#, 16#16#, 16#28#, 16#ae#, 16#d2#, 16#a6#,
          16#ab#, 16#f7#, 16#15#, 16#88#, 16#09#, 16#cf#, 16#4f#, 16#3c#];
      Init_Vector : constant Bytes :=
         [16#f0#, 16#f1#, 16#f2#, 16#f3#, 16#f4#, 16#f5#, 16#f6#, 16#f7#,
          16#f8#, 16#f9#, 16#fa#, 16#fb#, 16#fc#, 16#fd#, 16#fe#, 16#ff#];
      Input : constant Bytes :=
         [16#6b#, 16#c1#, 16#be#, 16#e2#, 16#2e#, 16#40#, 16#9f#, 16#96#,
          16#e9#, 16#3d#, 16#7e#, 16#11#, 16#73#, 16#93#, 16#17#, 16#2a#,
          16#ae#, 16#2d#, 16#8a#, 16#57#, 16#1e#, 16#03#, 16#ac#, 16#9c#,
          16#9e#, 16#b7#, 16#6f#, 16#ac#, 16#45#, 16#af#, 16#8e#, 16#51#,
          16#30#, 16#c8#, 16#1c#, 16#46#, 16#a3#, 16#5c#, 16#e4#, 16#11#,
          16#e5#, 16#fb#, 16#c1#, 16#19#, 16#1a#, 16#0a#, 16#52#, 16#ef#,
          16#f6#, 16#9f#, 16#24#, 16#45#, 16#df#, 16#4f#, 16#9b#, 16#17#,
          16#ad#, 16#2b#, 16#41#, 16#7b#, 16#e6#, 16#6c#, 16#37#, 16#10#];
      Expected : constant Bytes :=
         [16#87#, 16#4d#, 16#61#, 16#91#, 16#b6#, 16#20#, 16#e3#, 16#26#,
          16#1b#, 16#ef#, 16#68#, 16#64#, 16#99#, 16#0d#, 16#b6#, 16#ce#,
          16#98#, 16#06#, 16#f6#, 16#6b#, 16#79#, 16#70#, 16#fd#, 16#ff#,
          16#86#, 16#17#, 16#18#, 16#7b#, 16#b9#, 16#ff#, 16#fd#, 16#ff#,
          16#5a#, 16#e4#, 16#df#, 16#3e#, 16#db#, 16#d5#, 16#d3#, 16#5e#,
          16#5b#, 16#4f#, 16#09#, 16#02#, 16#0d#, 16#b0#, 16#3e#, 16#ab#,
          16#1e#, 16#03#, 16#1d#, 16#da#, 16#2f#, 16#be#, 16#03#, 16#d1#,
          16#79#, 16#21#, 16#70#, 16#a0#, 16#f3#, 16#00#, 16#9c#, 16#ee#];

      package AES128_CTR1 is new AES128.CTR (Init_Vector);
      Buf1 : AES128_CTR1.Buffer;
      Result : constant Bytes := Buf1.Xcrypt (Input);
   begin
      Assert (Result = Expected, "fail");
   end Test_AES128_Encrypt_CTR_2;

end Test_AES;
