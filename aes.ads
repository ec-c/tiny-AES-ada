generic
   type T is mod <>;
   type T_Index is range <>;
   type T_Array is array (T_Index range <>) of T;
package AES with
   SPARK_Mode
is

   type This_T is tagged limited private;
   type State_T is array (1 .. 4, 1 .. 4) of T;

   type Key_Length_T is (KL128, KL192, KL256);
   for Key_Length_T use (128, 192, 256);

   generic
      Key_Length : Key_Length_T;
   package EBC is
      procedure Encrypt (This : This_T; Buffer : T_Array);
      procedure Decrypt (This : This_T; Buffer : T_Array);
   end EBC;

   generic
      Key_Length : Key_Length_T;
   package CBC is
      procedure Encrypt (This : This_T; Buffer : T_Array);
      procedure Decrypt (This : This_T; Buffer : T_Array);
   end CBC;

   generic
      Key_Length : Key_Length_T;
   package CTR is
      procedure Xcrypt (This : This_T; Buffer : T_Array);
      procedure Encrypt (This : This_T; Buffer : T_Array) renames Xcrypt;
      procedure Decrypt (This : This_T; Buffer : T_Array) renames Xcrypt;
   end CTR;

private

   type This_T is
      tagged limited record
         State : State_T;
      end record;

   function Number_Of_Rounds (Key_Length : Key_Length_T) return Positive;
   pragma Inline (Number_Of_Rounds);

   function Number_Of_Words (Key_Length : Key_Length_T) return Positive;
   pragma Inline (Number_Of_Words);

   procedure Cipher (This : This_T; Round_Key : Positive);
   procedure Add_Round_Key (This : This_T);
   procedure Sub_Bytes (This : This_T);
   procedure Shift_Rows (This : This_T);
   procedure Mix_Columns (This : This_T);

end AES;
