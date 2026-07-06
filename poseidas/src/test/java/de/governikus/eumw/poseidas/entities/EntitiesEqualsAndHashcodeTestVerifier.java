package de.governikus.eumw.poseidas.entities;

import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;


@RequiredArgsConstructor
public class EntitiesEqualsAndHashcodeTestVerifier<T>
{

  private final EntityDescriptorI<T> entityDescriptor;


  /**
   * Executes all tests for the {@link EntityDescriptorI#getEntityClass()};
   */
  public DynamicTest createDynamicTest()
  {
    return DynamicTest.dynamicTest(entityDescriptor.getEntityClass().getSimpleName(), () -> {
      testFieldsMatch();
      testEquals();
      testNotEquals();
    });
  }

  /**
   * Tests if all fields of the class are mapped to be relevant or not relevant for the quals and hashcode methods.
   */
  private void testFieldsMatch()
  {
    List<String> classFields = Arrays.stream(entityDescriptor.getEntityClass().getDeclaredFields())
                                     .filter(f -> !Modifier.isStatic(f.getModifiers()))
                                     .map(Field::getName)
                                     .toList();
    List<String> knownFields = entityDescriptor.getKnownFields();


    List<String> unknownFields = new ArrayList<>(classFields);
    unknownFields.removeAll(knownFields);

    if (!unknownFields.isEmpty())
    {
      fail("The fields %s of class %s are not mapped as necessary for equals or not. Make sure to update the equals method".formatted(unknownFields,
                                                                                                                                      entityDescriptor.getEntityClass()
                                                                                                                                                      .getName()));
    }

    Assertions.assertEquals(classFields.stream().sorted().toList(),
                            knownFields.stream().sorted().toList(),
                            "It seems that there are more fields given then the class %s actually has. Where there fields removed?".formatted(entityDescriptor.getEntityClass()
                                                                                                                                                              .getName()));

  }

  @SneakyThrows
  private void testEquals()
  {
    T instanceOne = createInstance();

    // We create a new instance of the class under test and change the field under test.
    // Since that field was marked as not relevant for equals and hashcode we check if the two instances are still
    // equal.
    for ( String fieldNameUnderTest : entityDescriptor.getFieldNotRelevantForEquals() )
    {
      T changedInstance = createInstance();
      Field fieldUnderTest = entityDescriptor.getEntityClass().getDeclaredField(fieldNameUnderTest);
      if (Modifier.isFinal(fieldUnderTest.getModifiers()))
      {
        // We cannot and should not change final fields
        continue;
      }

      fieldUnderTest.setAccessible(true);
      fieldUnderTest.set(changedInstance, getValue(fieldUnderTest.getType(), false));

      checkRelevantFieldSet(changedInstance, fieldNameUnderTest);

      Assertions.assertEquals(instanceOne,
                              changedInstance,
                              "The field %s of class %s was set to to a different value than the comparing instance but the instances where not equal.".formatted(fieldNameUnderTest,
                                                                                                                                                                  entityDescriptor.getEntityClass()
                                                                                                                                                                                  .getName()));
      Assertions.assertEquals(instanceOne.hashCode(),
                              changedInstance.hashCode(),
                              "The field %s of class %s was set to to a different value than the comparing instance but the instances where not equal.".formatted(fieldNameUnderTest,
                                                                                                                                                                  entityDescriptor.getEntityClass()
                                                                                                                                                                                  .getName()));
    }
  }

  @SneakyThrows
  private void testNotEquals()
  {
    T instanceOne = createInstance();

    // We create a new instance of the class under test and change the field under test.
    // Since that field was marked as relevant for equals and hashcode we check if the two instances are not equal
    // anymore.
    for ( String fieldNameUnderTest : entityDescriptor.getFieldsRelevantForEquals() )
    {
      T wrongInstance = createInstance();
      Field fieldUnderTest = entityDescriptor.getEntityClass().getDeclaredField(fieldNameUnderTest);
      if (Modifier.isFinal(fieldUnderTest.getModifiers()))
      {
        fail("The field %s of class %s should not be part of the equals method because it is final.".formatted(fieldNameUnderTest,
                                                                                                               entityDescriptor.getEntityClass()
                                                                                                                               .getName()));
      }

      fieldUnderTest.setAccessible(true);
      fieldUnderTest.set(wrongInstance, getValue(fieldUnderTest.getType(), false));

      checkRelevantFieldSet(wrongInstance, fieldNameUnderTest);
      Assertions.assertNotEquals(instanceOne,
                                 wrongInstance,
                                 "The field %s of class %s was set to to a different value than the comparing instance but the instances where still equal.".formatted(fieldNameUnderTest,
                                                                                                                                                                       entityDescriptor.getEntityClass()
                                                                                                                                                                                       .getName()));
    }
  }


  @SneakyThrows
  private void checkRelevantFieldSet(T instance, String fieldName)
  {
    Field declaredField = null;
    try
    {
      declaredField = entityDescriptor.getEntityClass().getDeclaredField(fieldName);
    }
    catch (NoSuchFieldException e)
    {
      fail("Expected field %S is not present on class %s".formatted(fieldName,
                                                                    entityDescriptor.getEntityClass().getName()),
           e);
    }
    declaredField.setAccessible(true);

    Object value = declaredField.get(instance);

    if (declaredField.getType().isPrimitive())
    {
      return;
    }

    if (value == null)
    {
      fail("Field " + fieldName + " is not set on class " + entityDescriptor.getEntityClass().getName());
    }
  }

  private @NonNull T createInstance() throws InstantiationException, IllegalAccessException, InvocationTargetException
  {
    // We want the constructor with the most fields
    Optional<Constructor<?>> constructorOptional = Arrays.stream(entityDescriptor.getEntityClass()
                                                                                 .getDeclaredConstructors())
                                                         .max(Comparator.comparing(Constructor::getParameterCount));

    if (constructorOptional.isEmpty())
    {
      fail("The class %s only has an default constructor that can not be used for setting all parameters".formatted(entityDescriptor.getEntityClass()
                                                                                                                                    .getName()));
    }

    Constructor<?> constructor = constructorOptional.get();
    constructor.setAccessible(true);

    // We seach for a value for each constructor parameter by type
    Object[] parameters = Arrays.stream(constructor.getParameterTypes()).map(c -> this.getValue(c, true)).toArray();

    T instance = this.entityDescriptor.getEntityClass().cast(constructor.newInstance(parameters));
    for ( Field field : entityDescriptor.getEntityClass().getDeclaredFields() )
    {
      if (Modifier.isStatic(field.getModifiers()) || Modifier.isFinal(field.getModifiers()))
      {
        continue;
      }

      field.setAccessible(true);

      if (field.get(instance) == null)
      {
        Object value = getValue(field.getType(), true);
        field.set(instance, value);
      }
    }

    return instance;
  }

  /**
   * Returns one of two values for a specific class. The values differ by the value of the <i>firstValue</i> parameter.
   *
   * @param valueClass the class of the requested value.
   * @param firstValue true if the "first" value should be returned. false if a different (the second) value shall be
   *          returned.
   * @return one of two values of the given class.
   * @throws IllegalArgumentException when no value for a class could be found. Mostly because the class is unknown. Us
   *           the {@link EntityDescriptorI#getValueForClassExtension(String, boolean)} in this case. Native values can
   *           be added in this method.
   */
  private Object getValue(Class<?> valueClass, boolean firstValue)
  {
    String classSimpleName = valueClass.getSimpleName();

    // handle enums separately
    if (valueClass.isEnum())
    {
      Object[] constants = valueClass.getEnumConstants();
      return firstValue ? constants[0] : constants[Math.min(1, constants.length - 1)];
    }

    return switch (classSimpleName)
    {
      case "boolean" -> firstValue;
      case "byte", "int" -> firstValue ? 0x1 : 0x2;
      case "long", "Long" -> firstValue ? 1L : 2L;
      case "short" -> firstValue ? 0x1 : 0x3;
      case "char" -> firstValue ? '1' : '2';
      case "float" -> firstValue ? 1.0f : 2.0f;
      case "double" -> firstValue ? 1.0d : 2.0d;
      case "String" -> firstValue ? "first" : "second";
      case "Integer" -> firstValue ? 1 : 2;
      case "Date" -> firstValue ? new Date(1000L) : new Date(2000L);
      case "byte[]" -> firstValue ? new byte[]{1, 2, 3} : new byte[]{4, 5, 6};
      default -> entityDescriptor.getValueForClassExtension(classSimpleName, firstValue);
    };
  }

}
