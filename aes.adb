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

   function Number_Of_Rounds (Key_Length : Key_Length_T) return Positive is
   begin
      case Key_Length is
         when KL128 => return 10;
         when KL192 => return 12;
         when KL256 => return 14;
      end case;
   end Number_Of_Rounds;

   function Number_Of_Words (Key_Length : Key_Length_T) return Positive is
   begin
      case Key_Length is
         when KL128 => return 4;
         when KL192 => return 6;
         when KL256 => return 8;
      end case;
   end Number_Of_Words;

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
