package de.governikus.eumw.eidasmiddleware.projectconfig.database;


import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.StatementCallback;


@ExtendWith(MockitoExtension.class)
public class TimerHistoryConstraintDropperTest
{

  @Mock
  JdbcTemplate jdbcTemplate;

  @InjectMocks
  TimerHistoryConstraintDropper timerHistoryConstraintDropper;


  @Test
  void droppingTest()
  {
    // Mock existing constraint
    Mockito.when(jdbcTemplate.execute(Mockito.any(StatementCallback.class))).thenAnswer((Answer<String>)invocation -> {
      StatementCallback<String> argument = invocation.getArgument(0);
      Statement statementMock = Mockito.mock(Statement.class);

      Mockito.when(statementMock.execute(Mockito.anyString())).thenReturn(true);

      ResultSet resultSetMock = Mockito.mock(ResultSet.class);
      Mockito.when(statementMock.getResultSet()).thenReturn(resultSetMock);

      Mockito.when(resultSetMock.next()).thenReturn(true);

      Mockito.when(resultSetMock.getString(1)).thenReturn("TEST_CONSTRAINT_NAME");

      return argument.doInStatement(statementMock);
    });

    // Mock for sql alter execution
    ArgumentCaptor<String> stringArgumentCaptor = ArgumentCaptor.forClass(String.class);
    Mockito.doNothing().when(jdbcTemplate).execute(stringArgumentCaptor.capture());

    timerHistoryConstraintDropper.init();

    Mockito.verify(jdbcTemplate, Mockito.times(1)).execute(Mockito.any(StatementCallback.class));
    Mockito.verify(jdbcTemplate, Mockito.times(1)).execute(Mockito.any(String.class));

    Assertions.assertNotNull(stringArgumentCaptor.getValue());
    Assertions.assertEquals("ALTER TABLE TIMERHISTORY DROP CONSTRAINT TEST_CONSTRAINT_NAME",
                            stringArgumentCaptor.getValue());

  }

  @Test
  void nothingToDropTest()
  {
    // Mock not existing constraint
    Mockito.when(jdbcTemplate.execute(Mockito.any(StatementCallback.class))).thenAnswer((Answer<String>)invocation -> {
      StatementCallback<String> argument = invocation.getArgument(0);
      Statement statementMock = Mockito.mock(Statement.class);

      Mockito.when(statementMock.execute(Mockito.anyString())).thenReturn(true);

      ResultSet resultSetMock = Mockito.mock(ResultSet.class);
      Mockito.when(statementMock.getResultSet()).thenReturn(resultSetMock);

      Mockito.when(resultSetMock.next()).thenReturn(false);

      return argument.doInStatement(statementMock);
    });

    timerHistoryConstraintDropper.init();

    Mockito.verify(jdbcTemplate, Mockito.times(1)).execute(Mockito.any(StatementCallback.class));
    Mockito.verify(jdbcTemplate, Mockito.never()).execute(Mockito.any(String.class));


  }




  @ParameterizedTest
  @MethodSource("exceptions")
  void withDatabaseExceptionTest(Exception exception)
  {
    // Mock not existing constraint
    Mockito.when(jdbcTemplate.execute(Mockito.any(StatementCallback.class))).thenAnswer((Answer<String>)invocation -> {
      StatementCallback<String> argument = invocation.getArgument(0);
      Statement statementMock = Mockito.mock(Statement.class);

      Mockito.when(statementMock.execute(Mockito.anyString())).thenThrow(exception);

      return argument.doInStatement(statementMock);
    });

    // Check that no exception will be thorn from this method because it world brake the eumw.
    Assertions.assertDoesNotThrow(() -> timerHistoryConstraintDropper.init());

    Mockito.verify(jdbcTemplate, Mockito.times(1)).execute(Mockito.any(StatementCallback.class));
    Mockito.verify(jdbcTemplate, Mockito.never()).execute(Mockito.any(String.class));
  }


  @ParameterizedTest
  @MethodSource("exceptions")
  void withDatabaseExceptionOnDropTest(Exception exception)
  {
    // Mock existing constraint
    Mockito.when(jdbcTemplate.execute(Mockito.any(StatementCallback.class))).thenAnswer((Answer<String>)invocation -> {
      StatementCallback<String> argument = invocation.getArgument(0);
      Statement statementMock = Mockito.mock(Statement.class);

      Mockito.when(statementMock.execute(Mockito.anyString())).thenReturn(true);

      ResultSet resultSetMock = Mockito.mock(ResultSet.class);
      Mockito.when(statementMock.getResultSet()).thenReturn(resultSetMock);

      Mockito.when(resultSetMock.next()).thenReturn(true);

      Mockito.when(resultSetMock.getString(1)).thenReturn("TEST_CONSTRAINT_NAME");

      return argument.doInStatement(statementMock);
    });

    // Mock for sql alter execution
    ArgumentCaptor<String> stringArgumentCaptor = ArgumentCaptor.forClass(String.class);
    Mockito.doThrow(exception).when(jdbcTemplate).execute(stringArgumentCaptor.capture());

    // Check that no exception will be thorn from this method because it world brake the eumw.
    Assertions.assertDoesNotThrow(() -> timerHistoryConstraintDropper.init());

    Mockito.verify(jdbcTemplate, Mockito.times(1)).execute(Mockito.any(StatementCallback.class));
    Mockito.verify(jdbcTemplate, Mockito.times(1)).execute(Mockito.any(String.class));

    Assertions.assertNotNull(stringArgumentCaptor.getValue());
    Assertions.assertEquals("ALTER TABLE TIMERHISTORY DROP CONSTRAINT TEST_CONSTRAINT_NAME",
                            stringArgumentCaptor.getValue());

  }

  public static Stream<Arguments> exceptions()
  {
    return Stream.of(new CannotGetJdbcConnectionException("nothing"),
                     new BadSqlGrammarException(null, "sql", new SQLException()),
                     new NullPointerException(""))
                 .map(Arguments::of);
  }
}
