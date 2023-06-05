package org.fiware.iam.tir.repository;

import org.fiware.iam.satellite.model.TrustedCAVO;
import org.fiware.iam.tir.configuration.Party;

import java.util.List;
import java.util.Optional;

public interface PartiesRepo {

	List<Party> getParties();

	List<TrustedCAVO> getTrustedCAs();

	Optional<Party> getPartyById(String id);

	Optional<Party> getPartyByDID(String did);

	void addParty(Party party);
}
