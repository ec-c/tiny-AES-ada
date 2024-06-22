package body AES is

   package body EBC is

      procedure Encrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Encrypt;

      procedure Decrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Decrypt;

   end EBC;

   package body CBC is

      procedure Encrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Encrypt;

      procedure Decrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Decrypt;

   end CBC;

   package body CTR is

      procedure Xcrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Xcrypt;

   end CTR;

   procedure Cipher (This : This_T; Round_Key : Positive) is
   begin
      null;
   end Cipher;

   procedure Add_Round_Key (This : This_T) is
   begin
      null;
   end Add_Round_Key;

   procedure Sub_Bytes (This : This_T) is
   begin
      null;
   end Sub_Bytes;

   procedure Shift_Rows (This : This_T) is
   begin
      null;
   end Shift_Rows;

   procedure Mix_Columns (This : This_T) is
   begin
      null;
   end Mix_Columns;

end AES;
