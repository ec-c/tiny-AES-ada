generic
   type T is mod <>;
   type T_Index is range <>;
   type T_Array is array (T_Index range <>) of T;
   with function Shift_Left (Value : T; Amount : Natural) return T;
   with function Shift_Right (Value : T; Amount : Natural) return T;
package AES with
   SPARK_Mode,
   Pure
is

   type State_T is private;

   generic
   package CTR with
      SPARK_Mode
   is
      type Buffer is tagged limited private;

      function Xcrypt (This : Buffer; Buffer : T_Array) return T_Array;
   private

      type Buffer is
         tagged limited record
            Round_Key : T_Array (1 .. 176); -- AES128 -> 176
            State     : State_T;
         end record;

   end CTR;

private

   type State_T is array (1 .. 4, 1 .. 4) of T;

end AES;
