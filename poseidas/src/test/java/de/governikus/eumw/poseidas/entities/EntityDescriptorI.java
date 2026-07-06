package de.governikus.eumw.poseidas.entities;

import java.util.ArrayList;
import java.util.List;


/**
 * @param <T>
 */
interface EntityDescriptorI<T>
{

  /**
   * The class of the {@link jakarta.persistence.Entity} this {@link EntityDescriptorI} describes.
   */
  Class<T> getEntityClass();

  /**
   * All field names that are used in the equals and hashcode method. The {@link EntitiesEqualsAndHashcodeTestVerifier}
   * will automatically test each of these fields if the equal and hashcode method uses them.
   *
   * @return a list of the field names that are used in the equal and hashcode method.
   */
  List<String> getFieldsRelevantForEquals();

  /**
   * All field names that are <b>not</b> used in the equals and hashcode method. The
   * {@link EntitiesEqualsAndHashcodeTestVerifier} will automatically test each of these fields if the equal and
   * hashcode method ignores them.
   *
   * @return a list of the field names that are <b>not</b> used in the equal and hashcode method.
   */
  List<String> getFieldNotRelevantForEquals();

  /**
   * A helper method used to compare the fields listed in {@link EntityDescriptorI#getFieldNotRelevantForEquals()} and
   * {@link EntityDescriptorI#getFieldNotRelevantForEquals()} against the field of the class.
   *
   * @return all field names described in this {@link EntityDescriptorI}
   */
  default List<String> getKnownFields()
  {
    ArrayList<String> fieldNames = new ArrayList<>(getFieldsRelevantForEquals());
    fieldNames.addAll(getFieldNotRelevantForEquals());
    return fieldNames;
  }

  /**
   * Returns one of two values for a specific class. The values differ by the value of the <i>firstValue</i> parameter.
   * This method is intended to extend the {@link EntitiesEqualsAndHashcodeTestVerifier#getValue(Class, boolean)} in the
   * case that the entity described by this {@link EntityDescriptorI} has field with non-native types.
   *
   * @param className the simple class name of the requested value.
   * @param firstValue true if the "first" value should be returned. false if a different (the second) value shall be
   *          returned.
   * @return one of two values of the given class.
   * @throws IllegalArgumentException when no value for a class could be found. Mostly because the class is unknown.
   */
  default Object getValueForClassExtension(String className, boolean firstValue)
  {
    return switch (className)
    {
      case "null" -> null; // just to satisfy the compiler
      default -> throw new IllegalArgumentException("Cannot create %s value for class %s. Think about overriding the getValueForClassExtension method of your EntityDescriptor".formatted(firstValue
        ? "first" : "second", className));
    };
  }

}
