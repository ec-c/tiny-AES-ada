with Ahven;

with AES;

package body Test_AES is
   use Ahven;

   overriding
   procedure Initialize (Test : in out Test_T) is
   begin
      Set_Name (Test, "AES");

      Ahven.Framework.Add_Test_Routine (Test, Test_AES128_Encrypt_CTR'Access, "AES128 Encrypt CTR");
   end Initialize;

--   package AES128 is new AES (128, u8, Positive, Bytes, Interfaces.Shift_Left, Interfaces.Shift_Right);

   procedure Test_AES128_Encrypt_CTR is
      Key : Bytes := [16#2b#, 16#7e#, 16#15#, 16#16#, 16#28#, 16#ae#, 16#d2#, 16#a6#,
                      16#ab#, 16#f7#, 16#15#, 16#88#, 16#09#, 16#cf#, 16#4f#, 16#3c#];
      Input : Bytes := [16#60#, 16#1e#, 16#c3#, 16#13#, 16#77#, 16#57#, 16#89#, 16#a5#,
                        16#b7#, 16#a7#, 16#f5#, 16#04#, 16#bb#, 16#f3#, 16#d2#, 16#28#,
                        16#f4#, 16#43#, 16#e3#, 16#ca#, 16#4d#, 16#62#, 16#b5#, 16#9a#,
                        16#ca#, 16#84#, 16#e9#, 16#90#, 16#ca#, 16#ca#, 16#f5#, 16#c5#,
                        16#2b#, 16#09#, 16#30#, 16#da#, 16#a2#, 16#3d#, 16#e9#, 16#4c#,
                        16#e8#, 16#70#, 16#17#, 16#ba#, 16#2d#, 16#84#, 16#98#, 16#8d#,
                        16#df#, 16#c9#, 16#c5#, 16#8d#, 16#b6#, 16#7a#, 16#ad#, 16#a6#,
                        16#13#, 16#c2#, 16#dd#, 16#08#, 16#45#, 16#79#, 16#41#, 16#a6#];
      Init_Vector : Bytes := [16#f0#, 16#f1#, 16#f2#, 16#f3#, 16#f4#, 16#f5#, 16#f6#, 16#f7#,
                              16#f8#, 16#f9#, 16#fa#, 16#fb#, 16#fc#, 16#fd#, 16#fe#, 16#ff#];
      Output : Bytes := [16#6b#, 16#c1#, 16#be#, 16#e2#, 16#2e#, 16#40#, 16#9f#, 16#96#,
                         16#e9#, 16#3d#, 16#7e#, 16#11#, 16#73#, 16#93#, 16#17#, 16#2a#,
                         16#ae#, 16#2d#, 16#8a#, 16#57#, 16#1e#, 16#03#, 16#ac#, 16#9c#,
                         16#9e#, 16#b7#, 16#6f#, 16#ac#, 16#45#, 16#af#, 16#8e#, 16#51#,
                         16#30#, 16#c8#, 16#1c#, 16#46#, 16#a3#, 16#5c#, 16#e4#, 16#11#,
                         16#e5#, 16#fb#, 16#c1#, 16#19#, 16#1a#, 16#0a#, 16#52#, 16#ef#,
                         16#f6#, 16#9f#, 16#24#, 16#45#, 16#df#, 16#4f#, 16#9b#, 16#17#,
                         16#ad#, 16#2b#, 16#41#, 16#7b#, 16#e6#, 16#6c#, 16#37#, 16#10#];
      --  Result : Bytes := AES128.CTR.Encrypt (Input);
   begin
      Assert (1 = 2, "fail");
   end Test_AES128_Encrypt_CTR;

end Test_AES;
