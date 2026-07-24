import AutoLeanLibrary.Fixtures.ModelTheory.ClosedSentence
import AutoLeanLibrary.Fixtures.ModelTheory.OpenFormulaContext
import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

/-!
Terminal fixture for the pinned first-order model-theory compile spike.

It is intentionally not imported by `AutoLeanLibrary` or any promoted module.
The corresponding packet in `Library/records/` retains its non-promotion and
independent semantic-review and Builder-admission gap boundaries.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory

def compileSpikePacket : String := "round-01-model-theory-compile-spike"

end AutoLeanLibrary.Fixtures.ModelTheory
