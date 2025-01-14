#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
struct SyscallPass : PassInfoMixin<SyscallPass> {
    // Giriş Noktası
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        const DataLayout &DL = F.getParent()->getDataLayout();
        LLVMContext &Context = F.getContext();
        IRBuilder<> Builder(Context);

        // syscall fonksiyonunun tanımlanması
        FunctionCallee SyscallFunc = F.getParent()->getOrInsertFunction(
            "syscall", FunctionType::get(Type::getInt64Ty(Context),
                                         {Type::getInt64Ty(Context)},
                                         true));

        for (auto &BB : F) {
          for (auto I = BB.begin(), E = BB.end(); I != E; ++I) { // Tüm talimatların okunması
            Instruction *Inst = &*I;
            if (auto *Store = dyn_cast<StoreInst>(Inst)) { // Depolama talimatlarının ele alınması
              if (Store->getValueOperand()->getType()->isPointerTy()) {
                Builder.SetInsertPoint(Store->getNextNode());
                Value *Ptr = Store->getPointerOperand();

                Type *ElementType = Ptr->getElementType();
                uint64_t Size = DL.getTypeSizeInBits(ElementType);

                Builder.CreateCall(SyscallFunc, {Builder.getInt64(464), Ptr, Size}); // Şifreleme
              }
            }
            else if (auto *Load = dyn_cast<LoadInst>(Inst)) { // Yükleme talimatlarının ele alınması
              if (Load->getType()->isPointerTy()) {
                Builder.SetInsertPoint(Load);
                Value *Ptr = Load->getPointerOperand();

                Type *ElementType = Ptr->getElementType();
                uint64_t Size = DL.getTypeSizeInBits(ElementType);

                Builder.CreateCall(SyscallFunc, {Builder.getInt64(465), Ptr, Size}); // Deşifreleme
                Instruction *lastUse = nullptr;
                for (auto &U : Load->uses()) { // Son kullanımın belirlenmesi
                    if (auto *userInst = dyn_cast<Instruction>(U.getUser())) {
                         if (!lastUse) {
                            lastUse = userInst;
                        } else {
                            if (userInst->getParent() == lastUse->getParent()) {
                                for (auto &inst : *userInst->getParent()) {
                                    if (&inst == lastUse) break;
                                    if (&inst == userInst) {
                                        lastUse = userInst;
                                        break;
                                    }
                                }
                            } else {
                                lastUse = userInst;
                            }
                        }
                    }
                }
                if (lastUse) { // Son kullanımın değiştirilmesi
                    Builder.SetInsertPoint(lastUse->getNextNode());
                    Builder.CreateCall(SyscallFunc, {Builder.getInt64(464), Ptr, Size}); // Şifreleme
                }
              }
            }
          }
        }
        return PreservedAnalyses::all();
    }
};
} // namespace

PassPluginLibraryInfo getSyscallPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "SyscallPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, FunctionPassManager &FPM,
                       ArrayRef<PassBuilder::PipelineElement>) {
                      if (Name == "syscall-pass") {

                        FPM.addPass(SyscallPass());
                        return true;
                      }
                      return false;
                    });
                PB.registerPipelineStartEPCallback([](ModulePassManager &MPM,
                                                  OptimizationLevel Level) {

                    FunctionPassManager FPM;
                    FPM.addPass(SyscallPass());

                    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return getSyscallPassPluginInfo();
}