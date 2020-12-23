package de.governikus.eumw.poseidas.server.pki;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;


@Repository
public interface BlackListEntryRepository extends JpaRepository<BlackListEntry, BlackListEntryPK>
{


  public boolean existsByKey_SectorIDAndKey_SpecificID(String sectorId, String specificId);

  public List<BlackListEntry> findAllByKey_SectorID(String sectorId);

  @Transactional
  @Modifying
  @Query("DELETE FROM BlackListEntry b WHERE b.key.sectorID = ?1 and b.key.specificID in ?2")
  public void deleteAllByKey_SectorIDAndKey_SpecificIDIn(String sectorId, List<String> specificId);

  @Transactional
  @Modifying
  public void deleteAllByKey_SectorID(String sectorId);

  @Query("SELECT COUNT( b.key.specificID ) FROM BlackListEntry b WHERE b.key.sectorID = ?1")
  public Long countSpecifcIdWhereSectorId(String sectorID);

  @Query("UPDATE BlackListEntry b SET b.key.sectorID = ?2 WHERE b.key.sectorID = ?1")
  @Modifying
  public void updateToNewSectorId(String oldSectorID, String newSectorID);

}
