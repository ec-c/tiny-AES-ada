generic
   type T is mod <>;
   type T_Index is range <>;
   type T_Array is array (T_Index range <>) of T;
package AES with
   SPARK_Mode
is

   type State_T is tagged limited private;

   type Key_Length_T is (KL128, KL192, KL256);
   for Key_Length_T use (128, 192, 256);

   generic
      Key_Length : Key_Length_T;
   package EBC is
      procedure Encrypt (This : State_T);
      procedure Decrypt (This : State_T);
   end EBC;

   generic
      Key_Length : Key_Length_T;
   package CBC is
      procedure Encrypt (This : State_T);
      procedure Decrypt (This : State_T);
   end CBC;

   generic
      Key_Length : Key_Length_T;
   package CTR is
      procedure Xcrypt (This : State_T);
      procedure Encrypt (This : State_T) renames Xcrypt;
      procedure Decrypt (This : State_T) renames Xcrypt;
   end CTR;

private

   type State_T is
      tagged limited record
         Number_Of_Words : T_Index := 1;
      end record;

   procedure Cipher (This : State_T; Round_Key : Positive);
   procedure Add_Round_Key (This : State_T);
   procedure Sub_Bytes (This : State_T);
   procedure Shift_Rows (This : State_T);
   procedure Mix_Columns (This : State_T);

end AES;
