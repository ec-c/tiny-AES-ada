generic
   Key_Length : Positive; -- supports 128, 192 or 256 only
   type T is mod <>;
   type T_Index is range <>;
   type T_Array is array (T_Index range <>) of T;
package AES with
   SPARK_Mode
is

   type This_T is tagged limited private;
   type State_T is private;

   package EBC is
      procedure Encrypt (This : This_T; Buffer : T_Array);
      procedure Decrypt (This : This_T; Buffer : T_Array);
   end EBC;

   package CBC is
      procedure Encrypt (This : This_T; Buffer : T_Array);
      procedure Decrypt (This : This_T; Buffer : T_Array);
   end CBC;

   package CTR is
      procedure Xcrypt (This : This_T; Buffer : T_Array);
      procedure Encrypt (This : This_T; Buffer : T_Array) renames Xcrypt;
      procedure Decrypt (This : This_T; Buffer : T_Array) renames Xcrypt;
   end CTR;

private

   type State_T is array (1 .. 4, 1 .. 4) of T;

   type This_T is
      tagged limited record
         State : State_T;
      end record;

   procedure Cipher (This : This_T; Round_Key : Positive);
   procedure Add_Round_Key (This : This_T);
   procedure Sub_Bytes (This : This_T);
   procedure Shift_Rows (This : This_T);
   procedure Mix_Columns (This : This_T);

   pragma Precondition (Key_Length = 128 or else Key_Length = 192 or else Key_Length = 256);

end AES;
