import Mathlib.ModelTheory.Semantics

/-!
# A level-indexed universal fragment of classical two-sided `LK`

This is a non-promotable implementation fixture for the Builder quantifier-hygiene
spike.  It is deliberately only the `⊥`, `→`, and `∀` fragment: it is not full
`LK`, and compilation is not a Builder admission or a frozen statement contract.

The source-facing sequents in the pilot are closed.  Internally, a derivation at
level `n` uses formulas with free variables `Fin n`.  Universal-right moves to
level `n + 1`, lifts *both* old sides through `Fin.castSucc`, and opens the
quantifier body only at `Fin.last n`.  The public bridge below exists only at
level zero.

Source boundary: Open Logic Project, *Sets, Logic, Computation* (2026-07-12),
Definition 10.1, the Section 10.3 `LK` rules, and Theorem 10.28.  The retained
source record and page-level anchors live in the staging packet and Builder
quantifier-boundary note.  The level-indexed representation is an implementation
candidate under review, not a claim that the textbook uses this encoding.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

open FirstOrder
open FirstOrder.Language

universe u v

abbrev Fml (L : FirstOrder.Language) (n : Nat) := L.Formula (Fin n)

abbrev Body (L : FirstOrder.Language) (n : Nat) := L.BoundedFormula (Fin n) 1

abbrev Side (L : FirstOrder.Language) (n : Nat) := List (Fml L n)

/-- The disjoint old/new variable map used by universal-right. -/
def eigenExtend {n : Nat} : Fin n ⊕ Fin 1 → Fin (n + 1) :=
  Sum.elim Fin.castSucc fun _ => Fin.last n

@[simp]
theorem eigenExtend_inl {n : Nat} (i : Fin n) :
    eigenExtend (Sum.inl i) = Fin.castSucc i :=
  rfl

@[simp]
theorem eigenExtend_inr {n : Nat} (i : Fin 1) :
    eigenExtend (Sum.inr i) = Fin.last n :=
  rfl

/-- The fixed opening map cannot merge an old variable with the new one. -/
theorem eigenExtend_injective {n : Nat} : Function.Injective (@eigenExtend n) := by
  intro a b equality
  rcases a with a | a <;> rcases b with b | b
  · change Fin.castSucc a = Fin.castSucc b at equality
    exact congrArg Sum.inl (Fin.castSucc_injective n equality)
  · change Fin.castSucc a = Fin.last n at equality
    exact (Fin.castSucc_ne_last a equality).elim
  · change Fin.last n = Fin.castSucc b at equality
    exact (Fin.castSucc_ne_last b equality.symm).elim
  · exact congrArg Sum.inr (Subsingleton.elim a b)

/-- Lift an old free variable into the next level. -/
def wk {L : FirstOrder.Language} {n : Nat} (φ : Fml L n) : Fml L (n + 1) :=
  φ.relabel Fin.castSucc

/-- Both sides of a universal-right premise use this same structural lift. -/
def wkCtx {L : FirstOrder.Language} {n : Nat} (Γ : Side L n) : Side L (n + 1) :=
  Γ.map wk

/--
Turn the single in-scope bound variable into the new last free variable.
Old free variables remain in the image of `Fin.castSucc`.
-/
def openLast {L : FirstOrder.Language} {n : Nat} (body : Body L n) : Fml L (n + 1) :=
  body.toFormula.relabel eigenExtend

/--
Instantiate the single in-scope bound variable with a term.  This goes through
mathlib's capture-avoiding `BoundedFormula.subst`; it is not textual replacement.
-/
def inst0 {L : FirstOrder.Language} {n : Nat} (body : Body L n)
    (term : L.Term (Fin n)) : Fml L n :=
  body.toFormula.subst (Sum.elim Term.var fun _ => term)

/-- No old variable is confused with the eigenvariable introduced by `openLast`. -/
theorem castSucc_ne_last {n : Nat} (i : Fin n) : Fin.castSucc i ≠ Fin.last n :=
  Fin.castSucc_ne_last i

section Semantics

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]
variable {n : Nat}

theorem wk_realize (φ : Fml L n) (assignment : Fin (n + 1) → M) :
    (wk φ).Realize assignment ↔ φ.Realize (assignment ∘ Fin.castSucc) := by
  simp [wk]

theorem openLast_realize (body : Body L n) (assignment : Fin (n + 1) → M) :
    (openLast body).Realize assignment ↔
      body.Realize (assignment ∘ Fin.castSucc) (fun _ => assignment (Fin.last n)) := by
  simp [openLast, eigenExtend, Function.comp_def, BoundedFormula.realize_toFormula]

theorem inst0_realize (body : Body L n) (term : L.Term (Fin n))
    (assignment : Fin n → M) :
    Formula.Realize (inst0 body term) assignment ↔
      body.Realize assignment (fun _ => term.realize assignment) := by
  calc
    Formula.Realize (inst0 body term) assignment ↔
        Formula.Realize body.toFormula
          (fun freeVar =>
            (Sum.elim Term.var (fun _ => term) freeVar).realize assignment) := by
      change
        BoundedFormula.Realize
            (body.toFormula.subst (Sum.elim Term.var fun _ => term))
            assignment default ↔
          BoundedFormula.Realize body.toFormula
            (fun freeVar =>
              (Sum.elim Term.var (fun _ => term) freeVar).realize assignment)
            default
      exact BoundedFormula.realize_subst
    _ ↔ body.Realize assignment (fun _ => term.realize assignment) := by
      rw [BoundedFormula.realize_toFormula]
      simp [Function.comp_def]

theorem all_realize (body : Body L n) (assignment : Fin n → M) :
    Formula.Realize body.all assignment ↔
      ∀ value : M, body.Realize assignment (fun _ => value) := by
  rw [Formula.Realize, BoundedFormula.realize_all]
  apply forall_congr'
  intro value
  have bound_assignment :
      Fin.snoc (default : Fin 0 → M) value = (fun _ : Fin 1 => value) := by
    funext i
    rw [show i = 0 from Fin.eq_zero i]
    exact Fin.snoc_last _ _
  rw [bound_assignment]

namespace Side

/-- Every antecedent formula is true under the explicit open assignment. -/
def AllRealize (assignment : Fin n → M) : Side L n → Prop
  | [] => True
  | φ :: Γ => φ.Realize assignment ∧ AllRealize assignment Γ

/-- At least one succedent formula is true under the explicit open assignment. -/
def AnyRealize (assignment : Fin n → M) : Side L n → Prop
  | [] => False
  | φ :: Δ => φ.Realize assignment ∨ AnyRealize assignment Δ

@[simp]
theorem allRealize_nil (assignment : Fin n → M) : AllRealize assignment ([] : Side L n) :=
  trivial

@[simp]
theorem allRealize_cons (assignment : Fin n → M) (φ : Fml L n) (Γ : Side L n) :
    AllRealize assignment (φ :: Γ) ↔
      φ.Realize assignment ∧ AllRealize assignment Γ :=
  Iff.rfl

@[simp]
theorem anyRealize_nil (assignment : Fin n → M) :
    ¬AnyRealize assignment ([] : Side L n) :=
  not_false

@[simp]
theorem anyRealize_cons (assignment : Fin n → M) (φ : Fml L n) (Δ : Side L n) :
    AnyRealize assignment (φ :: Δ) ↔
      φ.Realize assignment ∨ AnyRealize assignment Δ :=
  Iff.rfl

theorem wkCtx_allRealize (Γ : Side L n) (assignment : Fin (n + 1) → M) :
    AllRealize assignment (wkCtx Γ) ↔
      AllRealize (assignment ∘ Fin.castSucc) Γ := by
  induction Γ with
  | nil => rfl
  | cons φ Γ ih =>
      change
        (wk φ).Realize assignment ∧ AllRealize assignment (wkCtx Γ) ↔
          φ.Realize (assignment ∘ Fin.castSucc) ∧
            AllRealize (assignment ∘ Fin.castSucc) Γ
      rw [wk_realize, ih]

theorem wkCtx_anyRealize (Δ : Side L n) (assignment : Fin (n + 1) → M) :
    AnyRealize assignment (wkCtx Δ) ↔
      AnyRealize (assignment ∘ Fin.castSucc) Δ := by
  induction Δ with
  | nil => rfl
  | cons φ Δ ih =>
      change
        (wk φ).Realize assignment ∨ AnyRealize assignment (wkCtx Δ) ↔
          φ.Realize (assignment ∘ Fin.castSucc) ∨
            AnyRealize (assignment ∘ Fin.castSucc) Δ
      rw [wk_realize, ih]

end Side

/-- Two-sided sequent semantics in a fixed structure, with no default open assignment. -/
def ValidIn (M : Type u) [L.Structure M] (Γ Δ : Side L n) : Prop :=
  ∀ assignment : Fin n → M,
    Side.AllRealize assignment Γ → Side.AnyRealize assignment Δ

end Semantics

/-!
The calculus below has no structural completeness claim.  Its rule constructors
are just the source-calibrated kernel needed to test the quantifier boundary.
-/
inductive Deriv (L : FirstOrder.Language) :
    (n : Nat) → Side L n → Side L n → Prop
  | identity {n Γ Δ} (φ : Fml L n) :
      Deriv L n (φ :: Γ) (φ :: Δ)
  | falsumLeft {n Γ Δ} :
      Deriv L n ((⊥ : Fml L n) :: Γ) Δ
  | impLeft {n Γ Δ} {φ ψ : Fml L n}
      (left : Deriv L n Γ (φ :: Δ))
      (right : Deriv L n (ψ :: Γ) Δ) :
      Deriv L n (φ.imp ψ :: Γ) Δ
  | impRight {n Γ Δ} {φ ψ : Fml L n}
      (premise : Deriv L n (φ :: Γ) (ψ :: Δ)) :
      Deriv L n Γ (φ.imp ψ :: Δ)
  | allLeft {n Γ Δ} {body : Body L n} {term : L.Term (Fin n)}
      (premise : Deriv L n (inst0 body term :: Γ) Δ) :
      Deriv L n (body.all :: Γ) Δ
  | allRight {n Γ Δ} {body : Body L n}
      (premise :
        Deriv L (n + 1) (wkCtx Γ) (openLast body :: wkCtx Δ)) :
      Deriv L n Γ (body.all :: Δ)

namespace Deriv

section Soundness

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]
variable {n : Nat} {Γ Δ : Side L n}

theorem identity_sound (φ : Fml L n) :
    ValidIn M (φ :: Γ) (φ :: Δ) := by
  intro assignment antecedent
  exact Or.inl antecedent.1

theorem falsumLeft_sound :
    ValidIn M ((⊥ : Fml L n) :: Γ) Δ := by
  intro assignment antecedent
  exact (by simpa using antecedent.1)

theorem impLeft_sound {φ ψ : Fml L n}
    (left : ValidIn M Γ (φ :: Δ))
    (right : ValidIn M (ψ :: Γ) Δ) :
    ValidIn M (φ.imp ψ :: Γ) Δ := by
  intro assignment antecedent
  rcases antecedent with ⟨implication, antecedent⟩
  rcases left assignment antecedent with formula | succedent
  · exact right assignment ⟨implication formula, antecedent⟩
  · exact succedent

theorem impRight_sound {φ ψ : Fml L n}
    (premise : ValidIn M (φ :: Γ) (ψ :: Δ)) :
    ValidIn M Γ (φ.imp ψ :: Δ) := by
  intro assignment antecedent
  classical
  by_cases formula : φ.Realize assignment
  · rcases premise assignment ⟨formula, antecedent⟩ with consequent | succedent
    · exact Or.inl (fun _ => consequent)
    · exact Or.inr succedent
  · exact Or.inl (fun impossible => (formula impossible).elim)

theorem allLeft_sound {body : Body L n} {term : L.Term (Fin n)}
    (premise : ValidIn M (inst0 body term :: Γ) Δ) :
    ValidIn M (body.all :: Γ) Δ := by
  intro assignment antecedent
  apply premise assignment
  refine ⟨(inst0_realize body term assignment).2 ?_, antecedent.2⟩
  exact (all_realize body assignment).1 antecedent.1 (term.realize assignment)

theorem allRight_sound {body : Body L n}
    (premise :
      ValidIn M (wkCtx Γ) (openLast body :: wkCtx Δ)) :
    ValidIn M Γ (body.all :: Δ) := by
  intro assignment antecedent
  classical
  by_cases oldSuccedent : Side.AnyRealize assignment Δ
  · exact Or.inr oldSuccedent
  · apply Or.inl
    apply (all_realize body assignment).2
    intro value
    let extended : Fin (n + 1) → M := Fin.snoc assignment value
    have liftedAntecedent : Side.AllRealize extended (wkCtx Γ) := by
      apply (Side.wkCtx_allRealize Γ extended).2
      simpa [extended] using antecedent
    rcases premise extended liftedAntecedent with opened | liftedSuccedent
    · have openedBody := (openLast_realize body extended).1 opened
      have extended_old : extended ∘ Fin.castSucc = assignment := by
        funext i
        simp [extended]
      rw [extended_old] at openedBody
      simpa [extended] using openedBody
    · exfalso
      apply oldSuccedent
      have oldBody := (Side.wkCtx_anyRealize Δ extended).1 liftedSuccedent
      have extended_old : extended ∘ Fin.castSucc = assignment := by
        funext i
        simp [extended]
      rwa [extended_old] at oldBody

theorem sound (derivation : Deriv L n Γ Δ) : ValidIn M Γ Δ := by
  induction derivation with
  | identity φ => exact identity_sound φ
  | falsumLeft => exact falsumLeft_sound
  | impLeft left right ihLeft ihRight =>
      exact impLeft_sound ihLeft ihRight
  | impRight premise ih => exact impRight_sound ih
  | allLeft premise ih => exact allLeft_sound ih
  | allRight premise ih => exact allRight_sound ih

end Soundness

end Deriv

section ClosedBridge

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]

/-- The only public statement adapter in this spike: level-zero formulas become sentences. -/
def close (φ : Fml L 0) : L.Sentence :=
  φ.relabel Fin.elim0

theorem close_realize (φ : Fml L 0) (assignment : Fin 0 → M) :
    M ⊨ close φ ↔ φ.Realize assignment := by
  rw [close, Sentence.Realize, Formula.realize_relabel]
  have assignments_equal : (default : Empty → M) ∘ Fin.elim0 = assignment :=
    Subsingleton.elim _ _
  rw [assignments_equal]

theorem close_sequent_realize (Γ Δ : Side L 0) :
    ValidIn M Γ Δ ↔
      (Side.AllRealize (Fin.elim0 : Fin 0 → M) Γ →
        Side.AnyRealize (Fin.elim0 : Fin 0 → M) Δ) := by
  constructor
  · intro valid
    exact valid (Fin.elim0 : Fin 0 → M)
  · intro valid assignment
    have assignments_equal : assignment = (Fin.elim0 : Fin 0 → M) :=
      Subsingleton.elim _ _
    simpa [assignments_equal] using valid

/-- Every source-boundary antecedent is realized as a closed sentence. -/
def ClosedAll (M : Type u) [L.Structure M] : Side L 0 → Prop
  | [] => True
  | φ :: Γ => M ⊨ close φ ∧ ClosedAll M Γ

/-- Some source-boundary succedent is realized as a closed sentence. -/
def ClosedAny (M : Type u) [L.Structure M] : Side L 0 → Prop
  | [] => False
  | φ :: Δ => M ⊨ close φ ∨ ClosedAny M Δ

theorem closedAll_iff (Γ : Side L 0) :
    ClosedAll M Γ ↔ Side.AllRealize (Fin.elim0 : Fin 0 → M) Γ := by
  induction Γ with
  | nil => rfl
  | cons φ Γ ih =>
      change
        (M ⊨ close φ ∧ ClosedAll M Γ) ↔
          Formula.Realize φ Fin.elim0 ∧
            Side.AllRealize (Fin.elim0 : Fin 0 → M) Γ
      rw [close_realize φ Fin.elim0, ih]

theorem closedAny_iff (Δ : Side L 0) :
    ClosedAny M Δ ↔ Side.AnyRealize (Fin.elim0 : Fin 0 → M) Δ := by
  induction Δ with
  | nil => rfl
  | cons φ Δ ih =>
      change
        (M ⊨ close φ ∨ ClosedAny M Δ) ↔
          Formula.Realize φ Fin.elim0 ∨
            Side.AnyRealize (Fin.elim0 : Fin 0 → M) Δ
      rw [close_realize φ Fin.elim0, ih]

/--
The actual external soundness boundary: both sides are evaluated only as
`Language.Sentence`s.  The internal open-assignment theorem is not exported in
place of this bridge.
-/
theorem Deriv.closed_sound {Γ Δ : Side L 0} (derivation : Deriv L 0 Γ Δ) :
    ClosedAll M Γ → ClosedAny M Δ := by
  intro antecedent
  apply (closedAny_iff Δ).2
  exact derivation.sound (M := M) Fin.elim0 ((closedAll_iff Γ).1 antecedent)

end ClosedBridge

section RejectionControls

/--
The equality body `bound = free` is enough to expose the unsoundness of reusing
an old free variable as the universal-right eigenvariable.
-/
def boundEqFree : Body Language.empty 1 :=
  BoundedFormula.equal
    (Term.var (Sum.inr 0))
    (Term.var (Sum.inl 0))

/-- Reusing the old variable makes the opened instance reflexive, hence valid. -/
theorem reused_old_variable_premise_valid :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ValidIn Bool ([] : Side Language.empty 1)
      [inst0 boundEqFree (Term.var 0)] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro assignment _
  left
  rw [inst0_realize]
  simp [boundEqFree, BoundedFormula.Realize]

/--
But the corresponding universal conclusion is false in the two-element model.
This kernel-checked countermodel is why `Deriv.allRight` moves to a new level.
-/
theorem reused_old_variable_allRight_is_unsound :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ¬ValidIn Bool ([] : Side Language.empty 1) [boundEqFree.all] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro claimed
  have conclusion := claimed (fun _ => false) trivial
  rw [Side.anyRealize_cons] at conclusion
  rcases conclusion with conclusion | contradiction
  · have allValues := (all_realize boundEqFree (fun _ => false)).1 conclusion
    have := allValues true
    simp [boundEqFree, BoundedFormula.Realize] at this
  · exact contradiction.elim

/--
For the separate existential-left freshness control, `bound = z` has free
variables `z = 0` and a would-be eigenvariable `y = 1`.  Existential rules are
not constructors of `Deriv`; this body is only a retained rejection witness.
-/
def existsEqFree : Body Language.empty 2 :=
  BoundedFormula.equal
    (Term.var (Sum.inr 0))
    (Term.var (Sum.inl 0))

/-- Reusing `y` makes the bad existential-left premise the identity `y = z ⊢ y = z`. -/
theorem reused_old_variable_existsLeft_premise_valid :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ValidIn Bool
      [inst0 existsEqFree (Term.var 1)]
      [inst0 existsEqFree (Term.var 1)] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro _ antecedent
  exact Or.inl antecedent.1

/--
The corresponding conclusion `∃ x, x = z ⊢ y = z` is false at
`z = false, y = true`: the antecedent has witness `false`, while the succedent
is false.  Thus an existential-left eigenvariable must also be fresh from the
entire lower sequent.
-/
theorem reused_old_variable_existsLeft_is_unsound :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ¬ValidIn Bool
      [existsEqFree.ex]
      [inst0 existsEqFree (Term.var 1)] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro claimed
  let assignment : Fin 2 → Bool := ![false, true]
  have existential : Formula.Realize existsEqFree.ex assignment := by
    rw [Formula.Realize, BoundedFormula.realize_ex]
    refine ⟨false, ?_⟩
    simp [existsEqFree, assignment, BoundedFormula.Realize, Fin.snoc]
  have conclusion := claimed assignment ⟨existential, trivial⟩
  rcases conclusion with conclusion | contradiction
  · have opened :=
      (inst0_realize existsEqFree (Term.var 1) assignment).1 conclusion
    simp [existsEqFree, assignment, BoundedFormula.Realize] at opened
  · exact contradiction.elim

/--
A nested quantifier whose outer variable is instantiated by the free variable.
The inner variable is `Fin.last 1`; the outer variable is its `castSucc`
predecessor, so the two cannot be conflated.
-/
def captureBody : Body Language.empty 1 :=
  BoundedFormula.all <|
    BoundedFormula.equal
      (Term.var (Sum.inr (Fin.castSucc 0)))
      (Term.var (Sum.inr (Fin.last 1)))

/-- The formula produced by the classic erroneous capture is reflexively true. -/
def naivelyCaptured : Fml Language.empty 1 :=
  BoundedFormula.all <|
    BoundedFormula.equal
      (Term.var (Sum.inr 0))
      (Term.var (Sum.inr 0))

theorem naive_capture_would_be_true :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    Formula.Realize naivelyCaptured (fun _ => false) := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  simp [naivelyCaptured, Formula.Realize, BoundedFormula.Realize]

/--
The real capture-avoiding instance remains false: with the free variable set to
`false`, the inner universal can choose `true`.  A textual/de-Bruijn capture
would instead produce `naivelyCaptured` and change the truth value.
-/
theorem inst0_capture_avoiding_control :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ¬Formula.Realize (inst0 captureBody (Term.var 0)) (fun _ => false) := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro captured
  have correctlyInstantiated :=
    (inst0_realize captureBody (Term.var 0) (fun _ => false)).1 captured
  have innerTrue := (BoundedFormula.realize_all.mp correctlyInstantiated) true
  simp [BoundedFormula.Realize, Fin.snoc] at innerTrue

end RejectionControls

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
