package be.atbash.mp.jwt.util;

import java.util.Collection;

/**
 *
 */

public class Utils {


    /**
     * Returns <code>true</code> if the given collection is null or is empty.
     *
     * @param collection The collection to be checked on emptiness.
     * @return <code>true</code> if the given collection is null or is empty.
     */
    public static boolean isEmpty(Collection<?> collection) {
        return collection == null || collection.isEmpty();
    }

    public static boolean isEmpty(String string) {
        return string == null || string.isEmpty();
    }

    /**
     * Returns <code>true</code> if the given array is null or is empty.
     *
     * @param array The array to be checked on emptiness.
     * @return <code>true</code> if the given array is null or is empty.
     */
    public static boolean isEmpty(Object[] array) {
        return array == null || array.length == 0;
    }


}
