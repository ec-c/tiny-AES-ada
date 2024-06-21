generic
   type T is mod <>;
   type T_Index is range <>;
   type T_Array is array (T_Index range <>) of T;
package AES with
   SPARK_Mode
is

   type State is tagged limited private;

   type Key_Length_T is (AES128, AES192, AES256);
   for Key_Length_T use (128, 192, 256);

   generic
      Key_Length : Key_Length_T;
   package EBC is
      procedure Encrypt (This : State);
      procedure Decrypt (This : State);
   end EBC;

   generic
      Key_Length : Key_Length_T;
   package CBC is
      procedure Encrypt (This : State);
      procedure Decrypt (This : State);
   end CBC;

   generic
      Key_Length : Key_Length_T;
   package CTR is
      procedure Xcrypt (This : State);
      procedure Encrypt (This : State) renames Xcrypt;
      procedure Decrypt (This : State) renames Xcrypt;
   end CTR;

private

   type State is
      tagged limited record
         a : Integer;
      end record;

end AES;
