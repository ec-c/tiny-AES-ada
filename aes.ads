generic
   type T is mod <>;
   type T_Index is range <>;
   type T_Array is array (T_Index range <>) of T;

   with function Shift_Left (Value : T; Amount : Natural) return T;
   with function Shift_Right (Value : T; Amount : Natural) return T;
package AES with
   SPARK_Mode
is

   type State_T is private;
   type This_T is interface;

   package CTR is
      type This1_T is new This_T with private;

      procedure Xcrypt (This : This1_T; Buffer : T_Array);
      procedure Encrypt (This : This1_T; Buffer : T_Array) renames Xcrypt;
      procedure Decrypt (This : This1_T; Buffer : T_Array) renames Xcrypt;

   private

      type This1_T is new This_T with
         record
            Round_Key : T_Array (1 .. 176); -- AES128 -> 176
            State     : State_T;
         end record;

   end CTR;

private

   type State_T is array (1 .. 4, 1 .. 4) of T;

end AES;
